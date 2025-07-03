<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Order;
use Illuminate\Support\Facades\Auth;

class OrderController extends Controller
{
    public function submit(Request $request)
    {
        $request->validate([
            'customer_name' => 'required|string|max:100',
            'dessert_type' => 'required|string|in:malay,cold,cute,others', // define allowed types 
            'dessert_item' => 'required|string|max:100',
            'quantity' => 'required|integer|min:1|max:50',
        ], [
            'customer_name.required' => 'Please enter your name.',
            'dessert_type.in' => 'Please select a valid dessert type.',
            'quantity.max' => 'You can only order up to 50 items at once!',
        ]);

        // Store the order into database
        Order::create([
            'user_id' => Auth::id(), // 👈 Associate with logged-in user
            'customer_name' => $request->input('customer_name'),
            'dessert_type' => $request->input('dessert_type'),
            'dessert_item' => $request->input('dessert_item'),
            'quantity' => $request->input('quantity'),
        ]);

        // Redirect with a success message
        return redirect('/')->with('success', 'Order placed successfully! 🍰');
        
    }

    public function myOrders()
    {
        $orders = Order::where('user_id', Auth::id())->latest()->get();
        return view('my-orders', compact('orders'));
    }



}
