import {cookieHeader,originAllowed} from "../_lib/auth.js";
export async function onRequestPost({request}) {
  if (!originAllowed(request)) return new Response("Forbidden",{status:403});
  return Response.json({ok:true},{headers:{"Set-Cookie":cookieHeader("",0),"Cache-Control":"no-store"}});
}
