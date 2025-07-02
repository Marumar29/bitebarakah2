@extends('layouts.master')

@section('content')
<div class="container mt-5">
  <h2 class="mb-4">Order Your Dessert 🍨</h2>


  @if(session('success'))
  <div class="alert alert-success">
    {{ session('success') }}
  </div>
@endif

@if ($errors->any())
  <div class="alert alert-danger">
    <ul>
      @foreach ($errors->all() as $error)
        <li>{{ $error }}</li>
      @endforeach
    </ul>
  </div>
@endif


<form method="POST" action="{{ route('order.submit') }}">
@csrf
    

    <!-- name section -->
    <div class="mb-3">
      <label for="customer_name" class="form-label">Your Name</label>
      <input type="text" class="form-control" name="customer_name" id="customer_name" required>
    </div>

    <!-- email section -->
    <div class="mb-3">
      <label>Email</label>
      <input type="email" name="email" class="form-control" required>
    </div>

    <!-- Dessert Type -->
    <div class="mb-3">
      <label for="dessertType" class="form-label">Dessert Type</label>
      <select id="dessertType" name="dessert_type" class="form-select" required>
        <option value="">-- Select Type --</option>
        <option value="malay">Malay Desserts</option>
        <option value="cold">Cold Desserts</option>
        <option value="cute">Cute Desserts</option>
        <option value="others">Others</option>
      </select>
    </div>

    <!-- Dessert Item (changes based on type) -->
    <div class="mb-3">
      <label for="dessertItem" class="form-label">Dessert</label>
      <select id="dessertItem" name="dessert_item" class="form-select" required>
        <option value="">-- Select Dessert --</option>
      </select>
    </div>

    <!-- Quantity -->
    <div class="mb-3">
      <label for="quantity" class="form-label">Quantity</label>
      <input type="number" name="quantity" class="form-control" min="1" required>
    </div>

    <button type="submit" class="btn btn-success">Place Order</button>
    <a href="{{ route('orders.mine') }}" class="btn btn-outline-primary">View My Orders</a>
</form>

@endsection

@section('scripts')
<script>
  // 🍰 Dessert dropdown options
  const dessertOptions = {
    malay: [
      "Ondeh-Ondeh",
      "Kuih Lapis",
      "Seri Muka",
      "Kuih Ketayap",
      "Kuih Kaswi",
      "Kuih Cara Manis"
    ],
    cold: [
      "Mango Pudding",
      "Sago Gula Melaka",
      "Cendol",
      "Strawberry Ice Blended",
      "Fruit Jelly Cups",
      "Chocolate Ice-Cream"
    ],
    cute: [
      "Hanami Dango",
      "Ichigo Daifuku",
      "Kyaraben",
      "Unicorn Cupcakes",
      "Berry Tarts",
    ],
    others: [
      "Fudgy Brownies",
      "Bhocolate Bhip Bookies",
      "Mini Cheesecakes",
      "Banana Bread",
      "Pandan Cupcakes",
    ]
  };

  // 🍡 Update dessert list when type is selected
  document.getElementById('dessertType').addEventListener('change', function () {
    const selectedType = this.value;
    const dessertDropdown = document.getElementById('dessertItem');

    dessertDropdown.innerHTML = '<option value="">-- Select Dessert --</option>';

    if (dessertOptions[selectedType]) {
      dessertOptions[selectedType].forEach(function (dessert) {
        const option = document.createElement('option');
        option.value = dessert;
        option.text = dessert;
        dessertDropdown.appendChild(option);
      });
    }
  });

  // 💌 Auto-hide success alert after 4 seconds
  document.addEventListener('DOMContentLoaded', function () {
    setTimeout(function () {
      const alertBox = document.getElementById('success-alert');
      if (alertBox) {
        alertBox.style.transition = 'opacity 0.5s ease';
        alertBox.style.opacity = '0';
        setTimeout(() => {
          alertBox.style.display = 'none';
        }, 500);
      }
    }, 4000);
  });
</script>
@endsection


