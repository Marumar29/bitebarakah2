<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class ContentSecurityPolicy
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        $csp = "default-src 'self'; ";
        $csp .= "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; ";
        $csp .= "style-src 'self' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; ";
        $csp .= "font-src 'self' https://fonts.gstatic.com data:; ";
        $csp .= "img-src 'self' data:; ";
        $csp .= "object-src 'none'; ";
        $csp .= "frame-ancestors 'none';"; // Anti-clickjacking

        $response->headers->set('Content-Security-Policy', $csp);
        $response->headers->set('X-Frame-Options', 'DENY'); // Clickjacking protection
        $response->headers->set('X-Content-Type-Options', 'nosniff'); // MIME sniffing prevention

        return $response;
    }
}
