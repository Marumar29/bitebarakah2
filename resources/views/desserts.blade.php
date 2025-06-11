@extends('layouts.master')

@section('content')

<section class="menu section-bg">
  <div class="container">
    <div class="section-title">
      <h2>🍰 Our Desserts</h2>
      <p>Sweet treats full of love and barakah~</p>
    </div>

    <div class="row">
      <!-- Dessert Item 1 -->
      <div class="col-lg-4 col-md-6">
        <div class="menu-item">
          <img src="{{ asset('assets/img/dessert1.jpg') }}" class="img-fluid" alt="Dessert 1">
          <h4>Strawberry Shortcake</h4>
          <p>RM12.00</p>
        </div>
      </div>

      <!-- Dessert Item 2 -->
      <div class="col-lg-4 col-md-6">
        <div class="menu-item">
          <img src="{{ asset('assets/img/dessert2.jpg') }}" class="img-fluid" alt="Dessert 2">
          <h4>Chocolate Lava Cake</h4>
          <p>RM15.00</p>
        </div>
      </div>

      <!-- Dessert Item 3 -->
      <div class="col-lg-4 col-md-6">
        <div class="menu-item">
          <img src="{{ asset('assets/img/dessert3.jpg') }}" class="img-fluid" alt="Dessert 3">
          <h4>Matcha Cheesecake</h4>
          <p>RM14.00</p>
        </div>
      </div>
    </div>

  </div>
</section>

@endsection
