"""Three bounded SOURCE groups: retained servicing, negatives, actual caller wiring."""
from pathlib import Path
import argparse,ast,copy,hashlib,importlib.util,json,sys,tempfile,time,urllib.error,ssl,http.client
from unittest.mock import patch
def check(v,c):
 if not v:raise RuntimeError(c)
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def held(C,code,fn):
 try:fn()
 except C.Hold as e:check(e.args==(code,),code);return
 raise RuntimeError('EXPECTED_'+code)
def group1(C,A,data):
 prior=[r for r in data['releases'] if r['security'] is True and r['runtime']['version']!='11.0.0'];check(len(prior)==3,'RETAINED_OLD_PREDICATE_FALSE_POSITIVE');result=C.validate_servicing(data,A);check(result=={'state':'EXACT_SUPPORTED_SELECTED_RELEASE_NO_LATER_SECURITY','runtime':'11.0.0','sdk':'11.0.100','releaseCount':11,'historicalSecurityReleases':3},'RETAINED_ACTUAL_SERVICING_ADMITTED');check(all(A.stable_compare('11.0.0',r['runtime']['version'])>0 for r in prior),'HISTORICAL_RC_PRECEDENCE')
 for version,expected in [('11.0.0-rc.3.26522.148',1),('11.0.0',0),('11.0.0+build.1',0),('11.0.1',-1),('11.0.1-rc.1',-1)]:check(A.stable_compare('11.0.0',C.servicing_version(version))==expected,'REVIEWED_PRECEDENCE')
 return {'originalBadPredicateMatches':3,'correctHistoricalSecurityRows':3,'latestPins':'11.0.100/11.0.0','exactOriginalDataUsed':True}
def group2(C,A,data):
 cases=[]
 for version in ('11.0.1','11.0.1-rc.1'):
  d=copy.deepcopy(data);row=copy.deepcopy(d['releases'][0]);row['runtime']['version']=row['release-version']=version;row['sdks'][0]['version']='11.0.101';d['releases'].append(row);cases.append((d,'LATER_SERVICING_REQUIRES_POLICY_HOLD'))
 d=copy.deepcopy(data);d['latest-sdk']='11.0.101';cases.append((d,'LATER_SERVICING_REQUIRES_POLICY_HOLD'))
 d=copy.deepcopy(data);d['latest-runtime']='11.0.1';cases.append((d,'LATER_SERVICING_REQUIRES_POLICY_HOLD'))
 d=copy.deepcopy(data);d['releases'][0]['sdks'][0]['version']='11.0.101';cases.append((d,'LATER_SERVICING_REQUIRES_POLICY_HOLD'))
 d=copy.deepcopy(data);d.pop('latest-runtime');cases.append((d,'SERVICING_VERSION_FORMAT'))
 d=copy.deepcopy(data);d['releases'][0]['security']='true';cases.append((d,'SERVICING_METADATA_SHAPE'))
 d=copy.deepcopy(data);d['releases'][0]['runtime']['version']='11.0.1-..PRIVATE';cases.append((d,'SERVICING_VERSION_FORMAT'))
 d=copy.deepcopy(data);d['releases'][0]['runtime'].pop('version');cases.append((d,'SERVICING_VERSION_FORMAT'))
 d=copy.deepcopy(data);d['releases'][0]['release-version']='11.0.0-rc.4';cases.append((d,'SERVICING_METADATA_INCONSISTENT'))
 d=copy.deepcopy(data);d['latest-release-date']='2026-11-09';cases.append((d,'SERVICING_METADATA_INCONSISTENT'))
 d=copy.deepcopy(data);d['latest-release-date']='2026-99-99';cases.append((d,'SERVICING_METADATA_SHAPE'))
 d=copy.deepcopy(data);d['releases'].append(copy.deepcopy(d['releases'][0]));cases.append((d,'EXACT_SDK_RUNTIME_SERVICING_MISSING'))
 d=copy.deepcopy(data);d['releases'][0]['sdks']=[];cases.append((d,'SERVICING_METADATA_SHAPE'))
 d=copy.deepcopy(data);d['releases'][1]['runtime']['version']='10.0.0-rc.1';d['releases'][1]['release-version']='10.0.0-rc.1';cases.append((d,'SERVICING_METADATA_INCONSISTENT'))
 for d,code in cases:held(C,code,lambda d=d:C.validate_servicing(d,A))
 for v in ('','11.0','011.0.0','11.0.0-rc.01','11.0.0-','11.0.0++bad',None,11):held(C,'SERVICING_VERSION_FORMAT',lambda v=v:C.servicing_version(v))
 tls=ssl.SSLCertVerificationError(1,'PRIVATE_TLS_REASON');tls.verify_code=20
 errors=[(urllib.error.HTTPError('https://example.invalid/PRIVATE',403,'PRIVATE',{},None),'METADATA_HTTP_ERROR','HTTP_ERROR',403,'UNKNOWN'),(urllib.error.URLError(OSError(13,'PRIVATE')),'METADATA_URL_IO','URL_ERROR','UNKNOWN','UNKNOWN'),(tls,'METADATA_TLS_IO','TLS_ERROR','UNKNOWN',20),(http.client.BadStatusLine('PRIVATE'),'METADATA_HTTP_PROTOCOL','HTTP_PROTOCOL_ERROR','UNKNOWN','UNKNOWN')]
 for exc,code,category,status,verify in errors:
  value=A.safe_metadata_failure(exc,'OPEN');check(value['code']==code and value['category']==category and value['httpStatus']==status and value['tlsVerifyCode']==verify and 'PRIVATE' not in json.dumps(value),'FINITE_PRECISE_IO_FAILURE')
 foreign=type('HTTPError',(RuntimeError,),{});value=A.safe_metadata_failure(foreign('PRIVATE'),'PRIVATE');check(value['code']=='UNKNOWN_OR_REDACTED' and value['operation']=='UNKNOWN' and 'PRIVATE' not in json.dumps(value),'FOREIGN_IO_CLASS_NOT_LAUNDERED')
 return {'negativeMetadataCases':len(cases),'malformedVersionCases':8,'actualLaterSecurityStillHold':True,'pinsNotChangedOrAutoSelected':True,'trustedHTTPURLTLSProtocolCategories':4,'rawExceptionOutput':False}
def group3(C,A,data,P,B,root):
 index='https://api.nuget.org/v3/vulnerabilities/index.json';repo='https://api.nuget.org/v3-index/repository-signatures/5.0.0/index.json';page='https://api.nuget.org/v3/vulnerabilities/2026.11.10/vulnerability.base.json';service='https://api.nuget.org/v3/index.json';servicing='https://builds.dotnet.microsoft.com/dotnet/release-metadata/11.0/releases.json';pki='http://example.invalid/fixture.crl';contract={'finiteMetadataAcquisition':{'sdkMetadataOnly':[{'url':service},{'url':servicing}],'PKIExactObservedGETs':[pki]}};calls=[];current=[data]
 def get(ctx,url,*args,**kwargs):
  calls.append(url)
  if url==service:ctx['boundOfficialPeer']=('192.0.2.1',443);value={'resources':[{'@type':'RepositorySignatures/5.0.0','@id':repo},{'@type':'VulnerabilityInfo/6.7.0','@id':index}]}
  elif url==repo:value={'signingCertificates':[{'fingerprints':{'2.16.840.1.101.3.4.2.1':C.REPOSITORY}}]}
  elif url==index:value=[{'@name':'base','@id':page,'@updated':'2026-11-10T00:00:00Z'}]
  elif url==page:value={}
  elif url==servicing:value=current[0]
  else:raise RuntimeError('UNDECLARED_FAKE_METADATA')
  return {'rawBytes':1,'decodedBytes':1},value
 def getpki(*args,**kwargs):calls.append(pki);raise C.Hold('FIXTURE_PKI_BOUNDARY')
 with patch.object(A,'bounded_json_get',side_effect=get),patch.object(A,'bounded_get',side_effect=getpki):
  d=root/'good';d.mkdir();held(C,'FIXTURE_PKI_BOUNDARY',lambda:C._metadata({'root':str(root),'startTick':0},d,contract,A,{'bodyBytes':0},None));check(calls[-1]==pki,'VALIDATED_METADATA_REACHES_UNCHANGED_PKI_BOUNDARY');calls.clear();bad=copy.deepcopy(data);bad['latest-runtime']='11.0.1';current[0]=bad;d=root/'bad';d.mkdir();held(C,'LATER_SERVICING_REQUIRES_POLICY_HOLD',lambda:C._metadata({'root':str(root),'startTick':0},d,contract,A,{'bodyBytes':0},None));check(pki not in calls,'LATER_SECURITY_STOPS_BEFORE_PKI_SDK')
 def funcs(p):return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(p.read_bytes()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 old,new=funcs(B/'tools/curate_dotnet11_linux_inputs.py'),funcs(P/'tools/curate_dotnet11_linux_inputs.py')
 for name in old:
  if name!='_metadata':check(old[name]==new[name],'UNCHANGED_FULL_PATH_'+name)
 before=json.loads((B/'tools/producer04-linux-curation.profile.json').read_bytes());after=json.loads((P/'tools/producer04-linux-curation.profile.json').read_bytes());causal={'safeCauseHelperSHA256','public10ProvenanceSHA256','advisoryHelperSHA256','diagnosticProfileSHA256'};check({k:v for k,v in before.items() if k not in causal}=={k:v for k,v in after.items() if k not in causal},'EXACT_ORIGINAL_CAPS_AND_TRUST_BINDINGS');return {'actualCallerPolicyBeforePKI':True,'laterVersionStopsBeforePKI':True,'fullMethodSDKCryptoAdvisoryAndBudgetsUnchanged':True,'fakeMetadataCallsOnly':True}
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args();D=args.root;P=D/'post';B=D/'baseline';started=time.perf_counter();files=[P/'tools/curate_dotnet11_linux_inputs.py',D/'frozen/curation_advisory_source04.py',P/'tools/producer04-linux-curation.profile.json',B/'tools/curate_dotnet11_linux_inputs.py',B/'tools/producer04-linux-curation.profile.json',D/'servicing.actual.wire',D/'FIXTURE.json',Path(__file__)];inputs=sum(x.stat().st_size for x in files);check(inputs<=524288,'SERIALIZED_INPUT512K');A=load('curation_advisory_source04',files[1]);C=load('curate_dotnet11_linux_inputs',files[0]);fixture=json.loads((D/'FIXTURE.json').read_bytes());wire=(D/'servicing.actual.wire').read_bytes();check(sha(wire)==fixture['wireSHA256'] and len(wire)==111610,'EXACT_RETAINED_WIRE');decoded=A.decode_json(wire,fixture['encoding'],4194304-len(wire));check(len(decoded)==594221 and sha(decoded)==fixture['sha256'],'EXACT_FULL_ORIGINAL_JSON');data=A.strict_json(decoded)
 one=group1(C,A,data);two=group2(C,A,data)
 with tempfile.TemporaryDirectory(dir=D) as tmp:three=group3(C,A,data,P,B,Path(tmp))
 elapsed=time.perf_counter()-started;check(elapsed<=30,'SOURCE30S');v={'schema':'producer04-servicing-causal-fixtures/v1','state':'THREE_NEW_CAUSAL_GROUPS_PASS','groups':3,'optimize':sys.flags.optimize,'seconds':elapsed,'inputBytes':inputs,'serializedFixtureBytes':len(wire),'decodedFixtureBytes':len(decoded),'rawPlusDecodedFixtureBytes':len(wire)+len(decoded),'decodedMetadataLimitBytes':4194304,'fixtureSHA256':fixture['sha256'],'sourceSHA256':{files[0].name:sha(files[0].read_bytes()),files[2].name:sha(files[2].read_bytes())},'frozenHelperSHA256':sha(files[1].read_bytes()),'testSHA256':sha(Path(__file__).read_bytes()),'evidence':[one,two,three],'actualHTTPDNSTLSJobSignalsSDKOpenSSLControllerCI':0,'healthySDKFullMethodOrOnlineDiagnosticReplay':0};raw=(json.dumps(v,indent=2)+'\n').encode();check(len(raw)<=32768,'OUTPUT32K');args.out.write_bytes(raw);print(json.dumps({'state':v['state'],'groups':3,'optimize':sys.flags.optimize,'seconds':round(elapsed,3),'inputBytes':inputs,'fixtureDecodedBytes':len(decoded),'outputBytes':len(raw),'actualHTTPDNSTLSJobSignalsSDKOpenSSLControllerCI':0}))
if __name__=='__main__':main()
