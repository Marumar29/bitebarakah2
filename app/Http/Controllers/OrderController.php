<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Order;

class OrderController extends Controller
{
    public function submit(Request $request)
    {
        // Store the order into database
        Order::create([
            'customer_name' => $request->input('customer_name'),
            'dessert_type' => $request->input('dessert_type'),
            'dessert_item' => $request->input('dessert_item'),
            'quantity' => $request->input('quantity'),
            'email' => $request->input('email'),
        ]);

        $request->validate([
            'customer_name' => 'required|string|max:255',
            'email' => 'required|email',
            'dessert_type' => 'required|string',
            'dessert_item' => 'required|string',
            'quantity' => 'required|integer|min:1',
        ]);

        $cleanName = strip_tags($request->input('customer_name'));

        // Redirect with a success message
        return redirect('/')->with('success', 'Order placed successfully! 🍰');
    }
}
