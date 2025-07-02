<p>Debug: Auth ID = {{ Auth::id() }}</p>

@extends('layouts.master')

@section('content')
<div class="container mt-5">
  <h2 class="mb-4">My Orders</h2>

  @if($orders->isEmpty())
    <p>No orders yet.</p>
  @else
    <table class="table table-bordered">
      <thead>
        <tr>
          <th>Dessert Type</th>
          <th>Dessert Item</th>
          <th>Quantity</th>
          <th>Ordered At</th>
        </tr>
      </thead>
      <tbody>
        @foreach ($orders as $order)
        <tr>
          <td>{{ ucfirst($order->dessert_type) }}</td>
          <td>{{ $order->dessert_item }}</td>
          <td>{{ $order->quantity }}</td>
          <td>{{ $order->created_at->format('d M Y, H:i') }}</td>
        </tr>
        @endforeach
      </tbody>
    </table>
  @endif
</div>
@endsection
