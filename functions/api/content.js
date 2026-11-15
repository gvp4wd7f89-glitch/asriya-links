import {validSession,originAllowed} from "../_lib/auth.js";
const DEFAULT_CONTENT = {branches:[],links:[],pageTitle:"روابط العصرية",intro:"كل روابط العصرية الرسمية في مكان واحد."};
export async function onRequestGet({request,env}) {
  if (!await validSession(request,env.ADMIN_SESSION_SECRET)) return Response.json({error:"يلزم تسجيل الدخول"},{status:401});
  const row=await env.DB.prepare("SELECT content_json, updated_at FROM site_content WHERE id=1").first();
  return Response.json({content:row?JSON.parse(row.content_json):DEFAULT_CONTENT,updatedAt:row?.updated_at||null},{headers:{"Cache-Control":"no-store"}});
}
export async function onRequestPut({request,env}) {
  if (!originAllowed(request)) return new Response("Forbidden",{status:403});
  if (!await validSession(request,env.ADMIN_SESSION_SECRET)) return Response.json({error:"يلزم تسجيل الدخول"},{status:401});
  let body; try { body=await request.json(); } catch { return Response.json({error:"بيانات غير صالحة"},{status:400}); }
  const c=body.content;
  if (!c || !Array.isArray(c.branches) || !Array.isArray(c.links) || typeof c.pageTitle!=="string" || typeof c.intro!=="string") return Response.json({error:"تركيبة البيانات غير صحيحة"},{status:400});
  if (JSON.stringify(c).length>100000) return Response.json({error:"حجم المحتوى أكبر من المسموح"},{status:413});
  for (const item of [...c.branches,...c.links]) {
    if (!item || typeof item.name!=="string" || typeof item.url!=="string" || !/^https:\/\//i.test(item.url)) return Response.json({error:"تحقق من أسماء الروابط وعناوينها (يجب أن تبدأ بـ https)"},{status:400});
  }
  await env.DB.prepare("INSERT INTO site_content (id,content_json,updated_at) VALUES (1,?,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET content_json=excluded.content_json,updated_at=CURRENT_TIMESTAMP").bind(JSON.stringify(c)).run();
  return Response.json({ok:true,updatedAt:new Date().toISOString()},{headers:{"Cache-Control":"no-store"}});
}
