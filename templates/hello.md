<!-- QR Code Section -->
        <div class="bg-white shadow-xl rounded-lg p-8 mb-8">
            <h2 class="text-2xl font-semibold text-gray-800 mb-4">QR Code for Event ID</h2>
            <div class="flex flex-col items-center">
                <img src="{{ url_for('generate_qr_code', event_id=event.unique_id) }}" alt="QR Code" class="w-64 h-64 rounded-md shadow-md mb-4">
                <button class="px-6 py-3 bg-green-600 text-white rounded-md hover:bg-green-700 transition duration-300" onclick="downloadQRCode()">Download QR Code</button>
            </div>
        </div>