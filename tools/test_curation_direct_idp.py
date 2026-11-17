"""Only new direct complete CRL IDP scope data cases; no native verification."""
import importlib.util
from pathlib import Path
p=Path(__file__).with_name('curation_linux_method.py');s=importlib.util.spec_from_file_location('scope',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def der(tag,data):
 n=len(data);length=bytes([n]) if n<128 else bytes([128+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big');return bytes([tag])+length+data
def names(*uris):return der(160,der(160,b''.join(der(134,u.encode()) for u in uris)))
def main():
 a='http://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl';b=a.replace('crl3','crl4');idp=der(48,names(a,b));cdp=der(48,der(48,names(a,b)))
 assert m.direct_complete_crl_scope({})==[]
 assert m.direct_complete_crl_scope({'2.5.29.28':idp})==[a,b]
 assert m.certificate_crl_uris(cdp)==[a,b]
 cases=[{'2.5.29.27':der(2,b'1')},{'2.5.29.28':der(48,names(a)+der(129,b'\xff'))},{'2.5.29.28':der(48,names(a)+der(130,b'\xff'))},{'2.5.29.28':der(48,names(a)+der(131,b'\x00'))},{'2.5.29.28':der(48,names(a)+der(132,b'\xff'))},{'2.5.29.28':der(48,names(a)+der(133,b'\xff'))},{'2.5.29.28':der(48,names(a,a))},{'2.5.29.28':der(48,names('http://user:pass@crl.example/x'))},{'2.5.29.28':der(48,names(a))+b'x'},{'2.5.29.28':der(48,der(160,der(161,b'x')))}]
 for value in cases:
  try:m.direct_complete_crl_scope(value)
  except m.Hold:continue
  raise RuntimeError('SCOPE_ACCEPTED_UNSUPPORTED_CASE')
 print({'newDataCases':13,'nativeOrSDKOrNetwork':0,'scope':'STRUCTURAL_ONLY_NOT_CRYPTO_PASS'})
if __name__=='__main__':main()
