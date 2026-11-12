import type {Metadata} from "next";
import "./globals.css";
export const metadata:Metadata={title:"ShadowGuard AI | Security Governance",description:"AI and SaaS security posture dashboard"};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>}
