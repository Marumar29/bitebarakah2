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
        ]);

        // Redirect with a success message
        return redirect('/')->with('success', 'Order placed successfully! 🍰');
    }
}
