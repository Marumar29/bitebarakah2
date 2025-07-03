<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class IsAdmin
{
    public function handle(Request $request, Closure $next)
    {
        // Replace with your admin emails
        $adminEmails = ['r.muhd.umar2922@gmail.com'];

        if (Auth::check() && in_array(Auth::user()->email, $adminEmails)) {
            return $next($request);
        }

        abort(403, 'Unauthorized access.');
    }
}

