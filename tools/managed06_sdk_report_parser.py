"""Bounded actual SDK report parsing only; never computes NuGet content hashes."""
import base64,binascii,hashlib,re
ROLE_LINES={
 'Verifying the author primary signature with certificate:',
 "Verifying author primary signature's timestamp with timestamping service certificate:",
 'Verifying the repository countersignature with certificate:',
 "Verifying repository countersignature's timestamp with timestamping service certificate:",
 'Verifying the repository primary signature with certificate:',
 "Verifying repository primary signature's timestamp with timestamping service certificate:",
}
def need(v,c):
 if not v:raise ValueError(c)
def _verified_block(stdout,package_id,version,raw):
 need(type(stdout) is bytes and len(stdout)<=65536,'ACTUAL_SUCCESSFUL_BOUNDED_PACKAGE_REPORT')
 text=stdout.decode('utf-8',errors='strict');need(not any(ord(c)<32 and c not in '\r\n\t' for c in text),'REPORT_CONTROL')
 lines=[x.strip() for x in text.splitlines()];identity=package_id+'.'+version
 blocks=[i for i,x in enumerate(lines) if x.startswith('Verifying ') and x not in ROLE_LINES];hashes=[i for i,x in enumerate(lines) if x.startswith('Content hash')];successes=[i for i,x in enumerate(lines) if x.startswith('Successfully verified package')]
 need(len(blocks)==len(hashes)==len(successes)==1,'EXACT_SINGLE_PACKAGE_HASH_SUCCESS');b,h,s=blocks[0],hashes[0],successes[0];need(lines[b]=='Verifying '+identity and lines[s]=="Successfully verified package '"+identity+"'." and b<h<s,'EXACT_IDENTITY_ORDER')
 match=re.fullmatch(r'Content hash: ([A-Za-z0-9+/]{86}==)',lines[h]);need(match is not None,'SDK_CONTENT_HASH_SCHEMA');value=match[1];decoded=base64.b64decode(value,validate=True);need(len(decoded)==64 and base64.b64encode(decoded).decode()==value,'SDK_CONTENT_HASH_CANONICAL')
 need(not any(re.search(r'\b(?:error|warning)\b|\bNU[0-9]{4}\b|validation failed|(?:revocation|chain|timestamp).*?(?:unknown|invalid|unavailable)|(?:unknown|invalid).*?(?:revocation|chain|timestamp)',x,re.I) for x in lines),'ANY_UNKNOWN_REVOCATION_OR_ISSUE_REQUIRES_HOLD')
 need(raw['id']==package_id and raw['version']==version and re.fullmatch('[0-9a-f]{64}',raw['sha256']) is not None,'RAW_BINDING')
 return {'id':package_id,'version':version,'rawSHA256':raw['sha256'],'normalizedNuGetContentHash':value,'hashAuthority':'Actual official SDK verify GetContentHash; no local normalized-hash formula','actualSDKLogSHA256':hashlib.sha256(stdout).hexdigest(),'reportedSignatureOutcome':'ACTUAL_PACKAGE_VERIFIED_NO_REPORTED_ISSUE','currentRevocationBoundary':'Standard online NuGet native Windows verification with reportUnknownRevocation enabled and all issue/unknown reports rejected; no independent current-validity claim for expired historic author/repository certificates.'}

def parse(stdout,package_id,version,exit_code,raw):
 need(exit_code==0,'ACTUAL_COMMAND_EXIT_ZERO_REQUIRED');v=_verified_block(stdout,package_id,version,raw);v.update(actualGlobalCommandExitCode=exit_code,actualPackageSuccess=True);return v

def parse_success_from_partial_command(stdout,package_id,version,actual_global_exit_code,raw):
 need(actual_global_exit_code==1,'ACTUAL_ORIGINAL_PARTIAL_COMMAND_EXIT_ONE');summaries=re.findall(rb'Finished with ([0-9]+) errors and ([0-9]+) warnings[.]',stdout);need(all(v==(b'0',b'0') for v in summaries),'NO_NONZERO_PACKAGE_SUMMARY');v=_verified_block(stdout,package_id,version,raw);v.update(actualGlobalCommandExitCode=actual_global_exit_code,actualPackageSuccess=True,originalCommandComplete=False,scope='Actual explicit independent SDK package success in a command that globally failed other package verifications. Global exit1 is preserved; no synthetic successful process code.');return v

def repository_leaf(stdout,allowed):
 lines=[s.strip() for s in stdout.decode('utf-8',errors='strict').splitlines()];labels={'Verifying the repository primary signature with certificate:','Verifying the repository countersignature with certificate:'};positions=[i for i,s in enumerate(lines) if s in labels];need(len(positions)==1,'EXACT_ONE_ACTUAL_REPOSITORY_SIGNATURE_ROLE');at=positions[0];end=next((i for i in range(at+1,len(lines)) if lines[i] in ROLE_LINES),len(lines));hashes=[re.fullmatch(r'SHA256 hash: ([A-Fa-f0-9]{64})',s) for s in lines[at+1:end]];values=[m[1].lower() for m in hashes if m];need(len(values)==1 and values[0] in allowed,'ACTUAL_SDK_REPOSITORY_LEAF_MATCHES_EXACT_OFFICIAL_ALLOWLIST');return {'role':lines[at],'certificateSHA256':values[0],'authority':'Actual SDK certificate block for repository primary or countersignature; extra primary-only CLI certificate filter is not used for an author signature.'}
