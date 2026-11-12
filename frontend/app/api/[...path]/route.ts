import {NextRequest,NextResponse} from "next/server";
async function proxy(req:NextRequest,ctx:{params:Promise<{path:string[]}>}){
const {path}=await ctx.params;const base=process.env.SHADOWGUARD_API_URL;const key=process.env.SHADOWGUARD_SERVICE_KEY;
if(!base||!key)return NextResponse.json({error:"Server API configuration missing"},{status:503});
const route=path.join("/");const read=req.method==="GET"&&["v1/dashboard","v1/apps","v1/incidents"].includes(route);
const write=req.method==="POST"&&["v1/telemetry/ingest","v1/policies/analyze"].includes(route);
const remediate=req.method==="POST"&&/^v1\/incidents\/\d+\/remediate$/.test(route);
if(!read&&!write&&!remediate)return NextResponse.json({error:"Route not allowed"},{status:404});
const body=req.method==="GET"?undefined:await req.text();
const upstream=await fetch(`${base.replace(/\/$/,"")}/api/${route}`,{method:req.method,headers:{"X-API-Key":key,...(body?{"Content-Type":"application/json"}:{})},body,cache:"no-store"});
return new NextResponse(await upstream.text(),{status:upstream.status,headers:{"Content-Type":upstream.headers.get("Content-Type")||"application/json","Cache-Control":"no-store"}});
}
export const GET=proxy;export const POST=proxy;
