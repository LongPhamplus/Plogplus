import asyncio
import httpx

async def fetch_cookies():
    url = "http://192.168.2.128/dvwa/login.php"  # httpbin sẽ đặt 1 cookie tên 'mycookie'

    async with httpx.AsyncClient() as client:
        response = await client.get(url)

        # In ra cookies đã nhận được từ server
        print("Cookies từ phản hồi:", response.cookies)

        # Thử gửi một request khác để xem cookie có được giữ lại không
        follow_up_response = await client.get(url)
        print("Cookies được gửi kèm request kế tiếp:", response.cookies)

asyncio.run(fetch_cookies())
