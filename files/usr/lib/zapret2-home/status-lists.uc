import { readfile } from 'fs';
let x=json(readfile('/dev/stdin'));
let s=x.base;
s.list_catalog=x.catalog;
s.list_state=x.meta.list_state ?? {};
s.update_running=x.meta.update_running ?? false;
s.update_error=x.meta.update_error ?? '';
print(sprintf('%J\n',s));
