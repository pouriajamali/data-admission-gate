"""Only new same-key trusted-parent choice cases; no native/SDK/network."""
import importlib.util
from pathlib import Path
p=Path(__file__).with_name('curation_linux_method.py');s=importlib.util.spec_from_file_location('parent',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
a={'sha256':'SDK_ANCHOR','SPKISHA256':'KEY'};b={'sha256':'CROSS_SIGNED','SPKISHA256':'KEY'}
assert m.select_current_parent([a],{}) is a
assert m.select_current_parent([b,a],{'SDK_ANCHOR':a}) is a
cases=[([a,b],{}),([a,dict(b,SPKISHA256='OTHER')],{'SDK_ANCHOR':a}),([a,b],{'SDK_ANCHOR':a,'CROSS_SIGNED':b}),([a,{'sha256':'MISSING_KEY'}],{'SDK_ANCHOR':a})]
for parents,anchors in cases:
 try:m.select_current_parent(parents,anchors)
 except m.Hold:continue
 raise RuntimeError('AMBIGUOUS_PARENT_ACCEPTED')
print({'newDataCases':6,'nativeOrSDKOrNetwork':0,'scope':'STRUCTURAL_ONLY_NOT_CRYPTO_PASS'})
