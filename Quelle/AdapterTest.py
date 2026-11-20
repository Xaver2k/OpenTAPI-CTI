import sys,threading,http.client,unittest,hmac,time,secrets
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from Adapter import Calls,Server,handler,private_ip
class Mock:
 def __init__(self):self.dest=[]
 def dial(self,n):self.dest.append(n)
class Tests(unittest.TestCase):
 def setUp(self):
  self.cs=[];self.srv=[];self.adapters=[]
  for i in range(2):
   c=Calls();a=Mock();self.cs.append(c);self.adapters.append(a)
   cfg=dict(telefon='127.0.0.1',token='a'*48,lokal='b'*48,nebenstelle=str(i))
   for loc in [False,True]:
    s=Server(('127.0.0.1',0),handler(cfg,c,a,loc));self.srv.append(s)
    threading.Thread(target=s.serve_forever,daemon=True).start()
 def tearDown(self):
  for s in self.srv:s.shutdown();s.server_close()
 def req(self,ix,method,path,body=None,auth=False):
  nonce=str(int(time.time()))+"-"+secrets.token_hex(16)
  headers={"X-CTI-Nonce":nonce,"X-CTI-Mac":hmac.digest(b"b"*48,(method+"|"+path+"|"+nonce+"|"+(body or "")).encode(),"sha256").hex()} if auth else {}
  if isinstance(auth,dict):headers=auth
  withconn=http.client.HTTPConnection(*self.srv[ix].server_address,timeout=2)
  try:
   withconn.request(method,path,body,headers)
   resp=withconn.getresponse()
   content=resp.read()
   if resp.status in (200,204) and ix%2:
    expected=hmac.digest(b"b"*48,b"reply|"+headers["X-CTI-Nonce"].encode()+b"|"+content,"sha256").hex()
    self.assertEqual(resp.getheader("X-CTI-Proof"),expected)
   return resp.status,content
  finally:withconn.close()
 def ev(self,i,e,n='%2B496912345',ident='call1'):
  return self.req(i,'GET','/event/'+'a'*48+'?ev='+e+'&id='+ident+'&n='+n)[0]
 def test_parallel(self):
  for i in [0,2]: self.assertEqual(self.ev(i,'in'),204)
  self.assertEqual(self.req(1,'GET','/calls',auth=True)[1],b'call1 ring in +496912345\n')
  self.ev(0,'up');self.ev(2,'end');self.ev(0,'in');self.ev(2,'in')
  self.assertIn(b'up in',self.cs[0].snapshot());self.assertFalse(self.cs[1].snapshot())
  self.ev(0,'end');self.assertFalse(self.cs[0].snapshot())
 def test_guard(self):
  self.assertEqual(self.req(0,'POST','/dial','123',True)[0],403)
  self.assertEqual(self.req(1,'POST','/dial','123')[0],403)
  self.assertEqual(self.req(1,'POST','/dial','12&3',True)[0],400)
  self.assertEqual(self.req(1,'POST','/dial','+49 (69) 123',True)[0],204)
  self.assertEqual(self.adapters[0].dest,['+4969123'])
  self.assertEqual(self.ev(0,'in',ident='$call_id'),400)
  self.ev(0,'in',n='anonymous');self.assertIn(b'ring in -',self.cs[0].snapshot())
 def test_after_answer(self):
  for c in self.cs: c.after_answer=True
  for i in [0,2]:self.ev(i,'in')
  for c in self.cs:self.assertEqual(c.snapshot(),b'')
  self.ev(2,'end');self.ev(0,'up');self.ev(2,'up')
  self.assertEqual(self.cs[0].snapshot(),b'call1 up in +496912345\n')
  self.assertEqual(self.cs[1].snapshot(),b'')
  self.ev(0,'end')
  self.assertEqual(self.cs[0].snapshot(),b'')
 def test_replay(self):
  nonce=str(int(time.time()))+"-"+secrets.token_hex(16)
  signed=hmac.digest(b"b"*48,("POST|/dial|"+nonce+"|21").encode(),"sha256").hex()
  hdr={"X-CTI-Nonce":nonce,"X-CTI-Mac":signed}
  self.assertEqual(self.req(1,"POST","/dial","22",hdr)[0],403)
  self.assertEqual(self.req(1,"POST","/dial","21",hdr)[0],204)
  self.assertEqual(self.req(1,"POST","/dial","21",hdr)[0],403)
  self.assertEqual(self.adapters[0].dest,["21"])
 def test_snom_call(self):
  from Adapter import event_url
  cfg=dict(pc="192.168.0.20",token="a"*48,profil="snom")
  self.assertIn("id=$csta_id",event_url(cfg,"up"))
  self.cs[0].after_answer=True
  self.ev(0,"in",n="sip:%2B491234@example.invalid",ident="-18")
  self.assertFalse(self.cs[0].snapshot())
  self.ev(0,"up",ident="-18")
  self.assertEqual(self.cs[0].snapshot(),b"-18 up in +491234\n")
  self.ev(0,"end",ident="-18")
  self.assertFalse(self.cs[0].snapshot())
 def test_ip(self):
  with self.assertRaises(ValueError):private_ip('0.0.0.0')
  with self.assertRaises(ValueError):private_ip('8.8.8.8')
if __name__=='__main__':unittest.main()
