
@extends('layouts.master')

@section('content')

<form method="GET" action="{{ route('admin.orders') }}" class="mb-4 row g-3">
  <div class="col-md-5">

    <input type="text" name="search" class="form-control" placeholder="Search by name..." value="{{ request('search') }}">
    <a href="{{ route('admin.downloadPDF') }}" class="btn btn-danger mb-3">⬇️ Download Orders as PDF</a>

  </div>

  <div class="col-md-4">
    <select name="dessert_type" class="form-select">
      <option value="">-- Filter by Dessert Type --</option>
      <option value="malay" {{ request('dessert_type') == 'malay' ? 'selected' : '' }}>Malay</option>
      <option value="cold" {{ request('dessert_type') == 'cold' ? 'selected' : '' }}>Cold</option>
      <option value="cute" {{ request('dessert_type') == 'cute' ? 'selected' : '' }}>Cute</option>
      <option value="others" {{ request('dessert_type') == 'others' ? 'selected' : '' }}>Others</option>
    </select>
  </div>

  <div class="col-md-3">
    <button type="submit" class="btn btn-primary">Filter</button>
    <a href="{{ route('admin.index') }}" class="btn btn-secondary">Reset</a>
  </div>
</form>

<div class="container mt-5">
  <h2 class="mb-4">Customer Orders</h2>

  <table class="table table-bordered table-hover">
    <thead class="table-dark">
      <tr>
        <th>#</th>
        <th>Name</th>
        <th>Dessert Type</th>
        <th>Dessert</th>
        <th>Quantity</th>
        <th>Ordered At</th>
      </tr>
    </thead>
    <tbody>
      @foreach($orders as $order)
      <tr>
        <td>{{ $loop->iteration }}</td>
        <td>{{ $order->customer_name }}</td>
        <td>{{ ucfirst($order->dessert_type) }}</td>
        <td>{{ $order->dessert_item }}</td>
        <td>{{ $order->quantity }}</td>
        <td>{{ $order->created_at->format('Y-m-d H:i') }}</td>
      </tr>
      @endforeach
    </tbody>
  </table>
</div>
@endsection
