<!DOCTYPE html>
<html>
<head>
    <title>Orders Report</title>
    <style>
        body { font-family: sans-serif; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            border: 1px solid #aaa;
            padding: 6px;
            text-align: left;
        }
        th {
            background-color: #eee;
        }
    </style>
</head>
<body>
    <h2>Order Report - BiteBarakah</h2>
    <table>
        <thead>
            <tr>
                <th>Customer</th>
                <th>Dessert Type</th>
                <th>Dessert</th>
                <th>Quantity</th>
                <th>Date</th>
            </tr>
        </thead>
        <tbody>
            @foreach ($orders as $order)
            <tr>
                <td>{{ $order->customer_name }}</td>
                <td>{{ ucfirst($order->dessert_type) }}</td>
                <td>{{ $order->dessert_item }}</td>
                <td>{{ $order->quantity }}</td>
                <td>{{ $order->created_at->format('Y-m-d') }}</td>
            </tr>
            @endforeach
        </tbody>
    </table>
</body>
</html>
