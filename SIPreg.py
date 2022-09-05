import random, string, time, threading
import socket, hashlib
from tkinter import *
from tkinter import scrolledtext
from functools import partial

def hashMD5(string):
    return hashlib.md5(string.encode()).hexdigest()

def randomString(lower=False, stringLength=32):
    if lower == False:
        lettersAndDigits = string.ascii_letters + string.digits
    else:
        lettersAndDigits = string.ascii_lowercase + string.digits
    return ''.join(random.choice(lettersAndDigits) for i in range(stringLength))
    
def findinstring(string, str1, str2):
    if string.find(str1) != -1:
        if str2 != "":
            return string.split(str1)[1].split(str2)[0]
        else:
            return string.split(str1)[1].split('\n')[0]
    else:
        return ""
        
def insert(string, str):
    if string.find("\n") != -1:
        s = string.split("\n")
        ind = len(s)
        for i in range(len(s)):
            if s[i].find("CSeq:") != -1:
                ind = i
        s.insert(ind, str)
        n = ""
        for i in range(len(s)):
            n += s[i] + "\n"
        return n
    else:
        return string

def findthread(name):
    for i in threading.enumerate():
        if i.name == name:
            return True
    return False

class sipphone(threading.Thread):
    def __init__(self, window, ip):
        threading.Thread.__init__(self)
        self.start()
        self.SERVER_IP = ip
        self.SRV_PORT = 5060
        self.USER = 'user'
        self.PASS = 'pass'
        
        self.CALLID = randomString(True)
        self.CSEQ = 1000
        
        self.REQUESTS = []
        self.REQSUM = 0
        self.RESPONSES = []
        self.RESPSUM = 0
        self.LASTCHK = 0
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1)
        
        self.window = window
        # self.kill = False
        # self.hang = False
        self.tkinter()
        
    def tkinter(self):
        self.window.title("SIP Phone")
        Label(self.window, text="Server IP:").grid(column=0, row=0)
        Label(self.window, text="Username:").grid(column=0, row=1)
        Label(self.window, text="Pasword:").grid(column=0, row=2) 
        Label(self.window, text="Status:").grid(column=0, row=4)
        Label(self.window, text="Call:").grid(column=0, row=5)
        Label(self.window, text="Accounts:").grid(column=2, row=0)
        Label(self.window, text="Requests:").grid(column=3, row=0)
        Label(self.window, text="Responses:").grid(column=4, row=0)
                
        self.e_serv = Entry(self.window, width=20, textvariable=StringVar(self.window, self.SERVER_IP)).grid(column=1, row=0)
        self.e_usr = Entry(self.window, width=20, textvariable=StringVar(self.window, "102")).grid(column=1, row=1)
        self.e_pass = Entry(self.window, width=20, textvariable=StringVar(self.window, "secondpass")).grid(column=1, row=2)
        self.e_status = Label(self.window, text="Offline").grid(column=1, row=4)
        self.e_call = Entry(self.window, width=20, textvariable=StringVar(self.window, "101")).grid(column=1, row=5)
        
        self.e_accounts = scrolledtext.ScrolledText(self.window, width=20).grid(column=2, row=1, rowspan=6)
        self.e_output = scrolledtext.ScrolledText(self.window, width=70).grid(column=3, row=1, rowspan=6)
        self.e_input = scrolledtext.ScrolledText(self.window, width=70).grid(column=4, row=1, rowspan=6)
        
        Button(self.window, text="Register", command=self.act_reg).grid(column=0, row=3)
        Button(self.window, text="Call", command=self.act_call).grid(column=0, row=6)
        Button(self.window, text="Log Out", command=self.act_logout).grid(column=1, row=3)
        Button(self.window, text="Hang", command=partial(self.act_hang, self.e_call.get())).grid(column=1, row=6)
        Button(self.window, text="Try Call", command=self.act_new).grid(column=1, row=4)
        
        deb = threading.Thread(name="debugger", target=self.debug, daemon=True)
        deb.start()
        lis = threading.Thread(name="listener", target=self.listen, daemon=True)
        lis.start()
        
    def stop(self):         
        self.window.destroy()
        exit()
    
    def act_reg(self):
        if findthread("register") == False:
            regi = threading.Thread(name="register", target=self.register, args=(self.e_serv.get(), self.e_usr.get(), self.e_pass.get()), daemon=True)
            regi.start()
        
    def act_call(self):
        if findthread("caller") == False:
            caller = threading.Thread(name="caller", target=self.call, args=(self.e_call.get(),), daemon=True)
            caller.start()
            
    def act_logout(self):
        if findthread("delogger") == False:
            delogger = threading.Thread(name="delogin", target=self.delogin, daemon=True)
            delogger.start()
        
    def act_hang(self, WHO):
        if findthread("byer") == False:
            byer = threading.Thread(name="byer", target=self.bye, args=(self.e_call.get(),))
            byer.start()
            
    def act_new(self):
        username='py_manager'
        password='managpass'
        phone_to_dial='100'
        local_user='101'
        p = "Action: Login\n"
        p += "ActionID: 1\n"
        p += "Events: on\n"
        p += "Username: "+username+"\n"
        p += "Secret: "+password+"\n"
        p += "\n"
        p += "Action: Originate\n"
        p += "ActionID: 2\n"
        p += "Channel: PJSIP/"+local_user+"/"+local_user+"\n"
        p += "Exten: "+phone_to_dial+"\n"
        p += "Context: from-internal\n"
        p += "Priority: 1\n"
        p += "\n"
        p += "\n"
        s = socket.socket()
        s.connect(('192.168.1.18',5038))
        for l in p.split('\n'):
            s.send((l+'\n').encode())
            if l == "":
                data = s.recv(1024)
                print(data.decode())
        data = s.recv(1024)
        s.close()
            
    def makemessage(self, TYPE, TYPE2, WHO):
        self.TAG = randomString(False)
        self.TAG2 = randomString(False)
        self.BRANCH = "z9hG4bKPj"+randomString(True)
        self.SERVICE_PORT = 63692
        REQUEST = ''
        if TYPE == "REGISTER":
            REQUEST += TYPE+' sip:'+self.SERVER_IP+' SIP/2.0\r\n'
            REQUEST += 'Via: SIP/2.0/UDP '+self.sock.getsockname()[0]+':'+str(self.SRV_PORT)+';rport;branch='+self.BRANCH+'\r\n'
        elif TYPE == "OK":
            REQUEST += 'SIP/2.0 200 '+TYPE+'\r\n'
            REQUEST += 'Via: SIP/2.0/UDP '+self.sock.getsockname()[0]+':'+str(self.SRV_PORT)+';rport;branch='+self.BRANCH+'\r\n'
        elif TYPE == "INVITE":
            REQUEST += TYPE+' sip:'+str(WHO)+'@'+self.SERVER_IP+' SIP/2.0\r\n'
            REQUEST += 'Via: SIP/2.0/UDP '+self.sock.getsockname()[0]+':'+str(self.SRV_PORT)+';rport;branch='+self.BRANCH+'\r\n'
        elif TYPE == "BYE":
            REQUEST += TYPE+' sip:'+self.SERVER_IP+':'+str(self.SRV_PORT)+' SIP/2.0\r\n'
            REQUEST += 'Via: SIP/2.0/UDP '+self.sock.getsockname()[0]+':'+str(self.SERVICE_PORT)+';rport;branch='+self.BRANCH+'\r\n'
        REQUEST += 'Call-ID: '+self.CALLID+'\r\n'
        REQUEST += 'From: <sip:'+self.USER+'@'+self.SERVER_IP+'>\r\n'
        REQUEST += 'To: <sip:'+str(WHO)+'@'+self.SERVER_IP+'>\r\n'
        REQUEST += 'Contact: <sip:'+self.USER+'@'+self.SERVER_IP+'>\r\n'
        if TYPE2 != "":
            REQUEST += 'CSeq: '+str(self.CSEQ)+' '+TYPE2+'\r\n'
        else:
            REQUEST += 'CSeq: '+str(self.CSEQ)+' '+TYPE+'\r\n'
        
        CONTENT = '\r\n'
        REQUEST += 'Content-Length:  '+str(len(CONTENT)-2)+'\r\n'
        REQUEST += CONTENT
        return REQUEST
        
    def replygen(self, CHALLENGE, TYPE):
        OPAQUE = findinstring(CHALLENGE, 'opaque="', '"')
        NONCE = findinstring(CHALLENGE, 'nonce="', '"')
        REALM = findinstring(CHALLENGE, 'realm="', '"')
        ALGORITHM = findinstring(CHALLENGE, 'algorithm=', ',')
        QOP = findinstring(CHALLENGE, 'qop="', '"')
        NONCE_COUNT = 1
        CNONCE = randomString(True)
        if ALGORITHM == "md5-sess":
            HA1H = hashMD5(hashMD5(self.USER+":"+REALM+":"+self.PASS)+":"+NONCE+":"+CNONCE)
        else:
            HA1H = hashMD5(self.USER+":"+REALM+":"+self.PASS)
        if QOP == "auth-int":
            HA2H = hashMD5(TYPE+":sip:"+self.SERVER_IP+":"+hashMD5(CHALLENGE))
        else:
            HA2H = hashMD5(TYPE+":sip:"+self.SERVER_IP)
        if QOP == "auth" or QOP == "auth-int":
            RESPONSE = hashMD5(HA1H+":"+NONCE+":00000001:"+CNONCE+":"+QOP+":"+HA2H)
        else:
            RESPONSE = hashMD5(HA1H+":"+NONCE+":"+HA2H)
        REPLY = 'Authorization: Digest username="'+self.USER+'", realm="'+REALM+'", nonce="'+NONCE+'", uri="sip:'+self.SERVER_IP+'", response="'+RESPONSE+'", algorithm="'+ALGORITHM+'", cnonce="'+CNONCE+'", opaque="'+OPAQUE+'", qop="'+QOP+'", nc="'+str(NONCE_COUNT).zfill(8)+'"\r'
        return REPLY
    
    def send(self, REQUEST):
        try:
            self.sock.sendto(bytes(REQUEST, "utf-8"), (self.SERVER_IP, self.SRV_PORT))
            self.REQUESTS.append(REQUEST)
            self.CSEQ += 1
        except Exception as e:
            print(e)

    def listen(self):
        while True:
            if self.kill == True:
                break
            time.sleep(0.1)
            try:
                RESPONSE = self.sock.recv(2048).decode()
                if RESPONSE:
                    if RESPONSE.find("NOTIFY sip") == -1 and RESPONSE.find("OPTIONS sip") == -1:  
                        self.RESPONSES.append(RESPONSE)
                else:
                    break
            except:
                pass
                
    def debug(self):
        t = 0
        while True:
            if self.kill == True:
                break
            time.sleep(0.1)
            if self.REQSUM < len(self.REQUESTS):
                self.e_output.insert(END, "\n"+self.REQUESTS[self.REQSUM])
                self.REQSUM += 1
                self.e_output.see(END)
            if self.RESPSUM < len(self.RESPONSES):
                self.e_input.insert(END, "\n"+self.RESPONSES[self.RESPSUM])
                self.RESPSUM += 1
                self.e_input.see(END)

    def reauth(self, REQUEST, last, TYPE):
        self.e_status["text"] = "Unauth."
        try:
            AUTH = insert(REQUEST, self.replygen(last, TYPE))
            self.send(AUTH)
        except Exception as e:
            print(e)

    def register(self, server_ip, user, password):
        self.SERVER_IP = server_ip
        self.USER = user
        self.PASS = password
        self.sock.connect((self.SERVER_IP, self.SRV_PORT))
        REQUEST = self.makemessage("REGISTER", "", self.USER)
        self.send(REQUEST)
        for t in range(100):
            time.sleep(0.1)
            if len(self.RESPONSES) == 0:
                break
            try:
                LMes = self.RESPONSES[self.LASTCHK]
                if LMes.find("SIP/2.0 200 OK") != -1 and LMes.find("REGISTER") != -1:
                    self.e_status["text"] = "Online."
                    self.LASTCHK += 1
                    break
                elif LMes.find("SIP/2.0 401 Unauthorized") != -1:
                    self.reauth(REQUEST, LMes, "REGISTER")
                else:
                    pass
            except:
                break
            if self.LASTCHK < len(self.RESPONSES):
                self.LASTCHK += 1
                
    def delogin(self):
        REQUEST = self.makemessage("REGISTER", "", self.USER)
        REQUEST = insert(REQUEST, 'Contact: *;expires=0\r')
        REQUEST = insert(REQUEST, "Expires: 0\r")
        self.send(REQUEST)
        for t in range(100):
            time.sleep(0.1)
            try:
                LMes = self.RESPONSES[self.LASTCHK]
                if LMes.find("SIP/2.0 200 OK") != -1 and LMes.find("REGISTER") != -1:
                    self.e_status["text"] = "Offline."
                    break
                elif LMes.find("SIP/2.0 401 Unauthorized") != -1:
                    self.reauth(REQUEST, LMes, "REGISTER")
                else:
                    pass
            except:
                break
            if self.LASTCHK < len(self.RESPONSES):
                self.LASTCHK += 1

    def call(self, WHO):
        self.hang = False
        REQUEST = self.makemessage("INVITE", "", WHO)
        self.send(REQUEST)
        t = 0
        while True:
            if self.kill == True or self.hang == True:
                t += 500
            if t > 200:
                self.e_status["text"] = "Timeout."
                self.send(self.makemessage("BYE", "BYE", WHO))
                break
            time.sleep(0.1)
            t += 1
            try:
                LMes = self.RESPONSES[self.LASTCHK]
            except:
                pass
            else:
                if LMes.find("SIP/2.0 200 OK") != -1 and LMes.find("INVITE") != -1:
                    self.e_status["text"] = "In call."
                    t = 0
                elif LMes.find("SIP/2.0 401 Unauthorized") != -1:
                    self.reauth(REQUEST, LMes, "INVITE")
                    t = 0
                elif LMes.find("SIP/2.0 100 Trying") != -1:
                    self.e_status["text"] = "Trying..."
                    t = 0
                elif LMes.find("SIP/2.0 180 Ringing") != -1:
                    self.e_status["text"] = "Ringing..."
                    t = 0
                elif LMes.find("BYE sip") != -1:
                    self.e_status["text"] = "Call end."
                    self.send(self.makemessage("OK", "BYE", WHO))
                    break
                else:
                    pass
                if self.LASTCHK < len(self.RESPONSES):
                    self.LASTCHK += 1
                    
    def bye(self, WHO):
        self.send(self.makemessage("BYE", "BYE", WHO))
        self.hang = True
        
if __name__ == "__main__":
    window = Tk()
    ip = "192.168.1.18"
    phone = sipphone(window, ip)
    window.protocol("WM_DELETE_WINDOW", phone.stop)
    window.mainloop()
    print("done")
    print(threading.enumerate())