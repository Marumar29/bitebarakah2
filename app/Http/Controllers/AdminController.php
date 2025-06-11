<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Order;
use Barryvdh\DomPDF\Facade\Pdf;

class AdminController extends Controller
{
    public function index()
    {
        return view('admin.index');
    }

    public function downloadPDF()
    {
        $orders = Order::all();
        $pdf = Pdf::loadView('admin.orders-pdf', compact('orders'));

        return $pdf->download('orders.pdf');
    }

    public function viewOrders(Request $request)
{
    $query = Order::query();

    if ($request->filled('search')) {
        $query->where('customer_name', 'like', '%' . $request->search . '%');
    }

    if ($request->filled('dessert_type')) {
        $query->where('dessert_type', $request->dessert_type);
    }

    $orders = $query->latest()->get();

    return view('admin.orders', ['orders' => $orders]);
}

}
