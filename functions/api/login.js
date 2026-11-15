import {passwordMatches,makeSession,cookieHeader,originAllowed} from "../_lib/auth.js";
export async function onRequestPost({request,env}) {
  if (!originAllowed(request)) return new Response("Forbidden",{status:403});
  let body; try { body=await request.json(); } catch { return Response.json({error:"طلب غير صالح"},{status:400}); }
  const password=String(body.password||"");
  if (!env.ADMIN_PASSWORD_HASH || !env.ADMIN_SESSION_SECRET) return Response.json({error:"إعدادات الدخول لم تكتمل في Cloudflare"},{status:503});
  if (password.length>200 || !await passwordMatches(password,env.ADMIN_PASSWORD_HASH)) return Response.json({error:"كلمة المرور غير صحيحة"},{status:401});
  const token=await makeSession(env.ADMIN_SESSION_SECRET);
  return Response.json({ok:true},{headers:{"Set-Cookie":cookieHeader(token),"Cache-Control":"no-store"}});
}
