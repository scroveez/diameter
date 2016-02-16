create or replace function allocate_ip_addr(
  p_pool in radpool.pool%type,
  p_expiry in radpool.expiry%type)
return radpool.yiaddr%type
is

v_ip radpool.yiaddr%type;
pragma autonomous_transaction;

begin

-- May need to alter this update statement to ensure the correct index is
-- used, otherwise the address chosen won't be the oldest available
update radpool r
set state = 1,
    expiry = p_expiry
where state = 0
and   pool = p_pool
and   rownum < 2
returning yiaddr into v_ip;

commit;

return v_ip;

exception when others then
  rollback;
  return null;
end;
/
