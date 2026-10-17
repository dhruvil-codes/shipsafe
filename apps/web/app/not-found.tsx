import { AppShell, ButtonLink, PageHeading } from "@/components/product-ui";
export default function NotFound() { return <AppShell><PageHeading eyebrow="404 · Page not found" title="This page isn’t here." description="The link may be outdated, or the page may have moved." /><div><ButtonLink href="/#scan">Scan your app →</ButtonLink></div></AppShell>; }
