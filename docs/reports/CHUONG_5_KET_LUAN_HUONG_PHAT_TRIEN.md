# CHƯƠNG 5: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

---

## 5.1. Tổng Kết Các Kết Quả Đạt Được Của Đề Tài

Sau quá trình nghiên cứu lý thuyết, phân tích thiết kế, cài đặt hiện thực hóa và tiến hành các chiến dịch thực nghiệm đo lường chuyên sâu, đề tài **"Nền tảng Giám sát, Phát hiện và Ngăn chặn Tấn công Web API dựa trên Trí tuệ Nhân tạo và Học máy kết hợp Môi trường Thao trường An ninh Mạng Đối kháng Phân tán"** đã hoàn thành xuất sắc toàn bộ các mục tiêu đặt ra, đạt được các kết quả nổi bật trên cả hai phương diện học thuật và kỹ thuật thực tiễn:

### 5.1.1. Đóng góp về mặt học thuật và phương pháp luận
1. **Thiết lập mô hình tri thức chuẩn hóa 20 trích dẫn:** Xây dựng thành công hệ thống cơ sở lý thuyết vững chắc dựa trên mô hình *Kiềng ba chân học thuật*: phối hợp hài hòa giữa 5 giáo trình an ninh và mật mã kinh điển (William Stallings, Douglas Stinson, Jonathan Katz & Yehuda Lindell, CompTIA PenTest+, NGINX Cookbook), 9 công trình bài báo quốc tế uy tín (Elsevier, IEEE, ACM, Wiley, MDPI) và 6 bộ tiêu chuẩn kỹ thuật an ninh thông tin quốc tế (NIST SP 800-115, ISO/IEC 27004:2016, OWASP Top 10, RFC 7807, RFC 9110).
2. **Chứng minh tính ưu việt của Kiến trúc Phòng thủ Đa tầng (Defense-in-Depth):** Khẳng định trên thực nghiệm rằng không có một thuật toán đơn lẻ nào có thể giải quyết trọn vẹn bài toán bảo vệ Web API. Sự kết hợp giữa *Động cơ Luật tất định (Rule Engine)* (chặn tức thời các tấn công kinh điển với độ trễ $0.010	ext{ ms}$), *Mô hình Phân loại Có giám sát (Random Forest)* (độ chính xác $99.93\%$, F1-Score $99.93\%$ trên tập mẫu đã biết) và *Mô hình Dị biệt Không giám sát (Isolation Forest)* (cô lập độc lập $24.00\%$ các biến thể Zero-day bị làm rối) đã tạo ra một hệ thống phòng thủ có khả năng tự phục hồi và thích ứng cao.
3. **Chứng minh năng lực tổng quát hóa của Vector 17 Đặc trưng Hình thái:** Đánh giá thực nghiệm trên tập dữ liệu chuẩn quốc tế CSIC 2010 đã chứng minh vector 17 đặc trưng thống kê hình thái chuỗi (kết hợp độ dài, Shannon Entropy, mật độ ký tự đặc biệt, cấu trúc phân nhánh) hoàn toàn độc lập với ngữ cảnh ứng dụng, cho phép mô hình duy trì độ chính xác $67.03\%$ và chặn $96.92\%$ tấn công XSS trên một hệ thống chưa từng được huấn luyện mà không bị quá khớp (Overfitting).

---

### 5.1.2. Kết quả về mặt kỹ thuật và triển khai thực tiễn
1. **Hiện thực hóa Thao trường An ninh Đối kháng Phân tán 2 Máy vật lý qua mạng LAN:** Xây dựng thành công môi trường thao trường thực chiến tách biệt hoàn toàn giữa Máy 1 (Blue Team) và Máy 2 (Red Team). Mọi luồng giao tiếp tấn công và phòng thủ đều diễn ra qua hạ tầng mạng nội bộ thực tế, phản ánh chính xác các yếu tố độ trễ phân tán, rung pha mạng (Jitter) và tính đồng thời kết nối.
2. **Cổng WAF Gateway Hiệu năng Cao và Chống Né tránh (Anti-Evasion):** Vận hành WAF Reverse Proxy Tầng 7 với thời gian xử lý nội bộ siêu tốc ($pprox 0.040	ext{ ms}$), hỗ trợ chuẩn hóa đệ quy 3 lớp (Recursive URL, HTML Entity, Unicode NFC), tích hợp động cơ ra quyết định rủi ro thích ứng (Hybrid Decision Engine) và thuật toán Token Bucket Rate Limiting kiểm soát tấn công từ chối dịch vụ. Hệ thống phản hồi mã lỗi chuẩn quốc tế RFC 7807 Problem Details.
3. **Làm chủ 100% Ứng dụng Mục tiêu Bookie Bookstore:** Tự thiết kế và lập trình hoàn chỉnh ứng dụng Web API thương mại điện tử với 8 kịch bản lỗ hổng nghiêm trọng chuẩn OWASP Top 10 Web & API, cung cấp điểm cuối đặc tả kỹ thuật OpenAPI 3.0 phục vụ trinh sát tự động.
4. **Tác tử Tấn công Tự động Sử dụng PyTorch Deep Q-Network Nội bộ:** Xây dựng thành công tác tử Red Team vận hành độc lập trên Máy 2, tự động trinh sát lược đồ OpenAPI và tự học chính sách biến dị payload né tránh WAF bằng mô hình học tăng cường sâu DQN (`evasion_agent.pt`) thuần túy bằng PyTorch, làm chủ hoàn toàn công nghệ lõi mà không cần phụ thuộc vào dịch vụ đám mây hay API bên ngoài.
5. **Trung tâm Chỉ huy Điều hành SOC Dashboard Thời Gian Thực:** Hoàn thiện bảng điều khiển giám sát an ninh Next.js 14 chuyên nghiệp, cung cấp 5 thẻ chỉ số an ninh thời gian thực, biểu đồ sóng lưu lượng song song, phân bố họ tấn công và ngăn kéo điều tra chứng cứ số (Evidence Drawer) hiển thị chi tiết chuỗi đầu vào trước và sau chuẩn hóa.

---

## 5.2. Các Hạn Chế Còn Tồn Tại (System Limitations)

Mặc dù đã đạt được nhiều kết quả tích cực, nhóm nghiên cứu cũng thẳng thắn nhìn nhận một số hạn chế kỹ thuật nhất định của hệ thống trong giai đoạn hiện tại:

1. **Hạn chế về Băng thông và Nghẽn Cổ chai I/O Cơ sở Dữ liệu:**
   - Hệ thống hiện tại đang sử dụng CSDL SQLite nội bộ cho việc lưu vết chi tiết từng request (`requests`) và sự kiện an ninh (`security_events`). Mặc dù thuận tiện cho việc đóng gói và kiểm thử trong môi trường học thuật, cơ chế khóa tệp (File Lock) của SQLite có thể gây nghẽn cổ chai I/O khi lưu lượng đồng thời tăng đột biến vượt ngưỡng $1.000	ext{ RPS}$.
2. **Phạm vi Nhận diện Định dạng Dữ liệu Đầu vào:**
   - Bộ bóc tách và trích xuất đặc trưng hiện tại tập trung tối ưu cho các định dạng văn bản chuẩn của REST API (JSON, Form-URL-encoded, Multipart và Query String). Hệ thống chưa hỗ trợ phân tích sâu các giao thức nhị phân hiệu năng cao như gRPC (Protocol Buffers) hoặc các câu truy vấn phân cấp phức tạp dạng GraphQL lồng nhau nhiều tầng.
3. **Thách thức Đối với Lỗ hổng Logic Nghiệp vụ Tinh vi (Business Logic & BOLA):**
   - Bộ trích xuất 17 đặc trưng hình thái tập trung phát hiện sự bất thường về mặt cú pháp và phân phối ký tự chuỗi. Do đó, đối với các cuộc tấn công vi phạm kiểm soát quyền truy cập ở mức đối tượng (BOLA/IDOR - OWASP API1:2023) mà kẻ tấn công chỉ đơn thuần thay đổi một ID hợp lệ (ví dụ: từ `orders/101` sang `orders/102`), payload hoàn toàn mang hình thái của một request sạch, khiến các mô hình học máy hình thái khó có thể phát hiện nếu không có thêm ngữ cảnh định danh phiên làm việc (Session Context).

---

## 5.3. Hướng Phát Triển và Mở Rộng Trong Tương Lai (Future Work)

Dựa trên các nền tảng kỹ thuật đã hoàn thiện và những hạn chế đã chỉ ra, nhóm nghiên cứu đề xuất các hướng phát triển chiến lược trong tương lai:

### 5.3.1. Nâng cấp bộ lọc tầng nhân Linux với công nghệ eBPF / XDP
- Chuyển giao một phần cơ chế đối sánh luật chữ ký tĩnh và giới hạn tần suất từ không gian người dùng (User Space - Python) xuống trực tiếp tầng nhân hệ điều hành Linux (Kernel Space) thông qua công nghệ **eBPF (Extended Berkeley Packet Filter)** và **XDP (eXpress Data Path)**.
- Giải pháp này giúp loại bỏ hoàn toàn chi phí sao chép gói tin qua socket (Zero-Copy), cho phép WAF ngắt kết nối các cuộc tấn công DoS/Brute Force ngay tại tầng cạc mạng (NIC Driver Level) với thông lượng hàng triệu gói tin/giây mà không tiêu tốn tài nguyên CPU.

---

### 5.3.2. Đóng gói thành Kubernetes Ingress Controller và Envoy Wasm Plugin
- Mở rộng phạm vi triển khai của Cổng WAF Gateway sang môi trường đám mây vi dịch vụ (Cloud-Native Microservices).
- Đóng gói logic phân loại đa tầng thành một **Kubernetes Ingress Controller** hoặc một **Envoy WebAssembly (Wasm) Plugin** tích hợp trực tiếp vào kiến trúc Service Mesh (Istio), cho phép bảo vệ phân tán cho toàn bộ hệ thống các API nội bộ mà không làm phát sinh thêm chặng chuyển tiếp mạng (Network Hop).

---

### 5.3.3. Ứng dụng Mô hình Ngôn ngữ Nhỏ Chuyên biệt (Security SLMs)
- Tích hợp các mô hình ngôn ngữ nhỏ được tinh chỉnh chuyên biệt cho an ninh mạng (Domain-Specific Security Small Language Models) đã được lượng tử hóa (Quantized 4-bit) để chạy cục bộ trên máy chủ biên.
- SLM sẽ được kích hoạt ở chế độ phân tích chuyên sâu (Deep Inspection) cho các request bị đánh dấu `MONITOR`, giúp phân tích sâu ngữ nghĩa câu lệnh và luồng dữ liệu nghiệp vụ, giải quyết triệt để bài toán phát hiện lỗ hổng BOLA/IDOR và Broken Function Level Authorization.

---

### 5.3.4. Vận hành Chu trình Đối kháng Học liên tục (Continuous Adversarial Red Teaming)
- Tự động hóa hoàn toàn chu trình khép kín giữa Red Team và Blue Team:
  1. Tác tử Tấn công PyTorch DQN liên tục tìm kiếm các biến thể payload mới né tránh được WAF.
  2. Khi phát hiện một mẫu vượt rào thành công, hệ thống tự động lưu mẫu vào kho lưu trữ đối kháng (Adversarial Data Store).
  3. Hệ thống WAF tự động trích xuất đặc trưng mới, cập nhật bổ sung luật chữ ký và kích hoạt tái huấn luyện liên tục mô hình học máy (Online Continual Retraining) mà không cần can thiệp thủ công từ con người.

---

## 5.4. Lời Kết

Đề tài nghiên cứu đã chứng minh tính khả thi, hiệu quả vượt trội và giá trị thực tiễn to lớn của việc kết hợp Trí tuệ Nhân tạo, Học máy đa tầng và Môi trường Thao trường Mạng Đối kháng Phân tán trong việc bảo vệ các hệ thống Web API hiện đại. Các kết quả học thuật, kiến trúc kỹ thuật và mã nguồn hoàn thiện của đề tài không chỉ đáp ứng xuất sắc các yêu cầu chuyên môn của học phần Đồ án PBL6, mà còn mở ra một hướng tiếp cận bài bản, hiện đại cho công tác nghiên cứu và triển khai an ninh mạng ứng dụng trong thực tế.
