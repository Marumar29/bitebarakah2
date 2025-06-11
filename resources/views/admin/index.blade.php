@extends('layouts.master')

@section('content')

<a href="{{ route('admin.orders') }}" class="btn btn-info">View Orders Table</a>

<div class="container mt-5">
    <h2>Welcome to the Admin Panel</h2>
    <p>This is the admin dashboard 💼</p>
</div>
@endsection
