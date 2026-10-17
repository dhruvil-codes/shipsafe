"use client";
import { AppShell, ErrorNotice } from "@/components/product-ui";
export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) { return <AppShell><h1>Something interrupted this page.</h1><ErrorNotice message="Your request could not be completed. Retry to retrieve the recorded state." retry={reset} /></AppShell>; }
