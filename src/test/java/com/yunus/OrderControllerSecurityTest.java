package com.yunus.controller;

import com.yunus.config.RestAccessDeniedHandler;
import com.yunus.config.RestAuthenticationEntryPoint;
import com.yunus.config.SecurityConfig;
import com.yunus.dto.order.OrderRequest;
import com.yunus.dto.order.OrderResponse;
import com.yunus.entity.User;
import com.yunus.enums.OrderStatus;
import com.yunus.enums.Role;
import com.yunus.model.UserPrincipal;
import com.yunus.service.CustomUserDetailsService;
import com.yunus.service.JwtService;
import com.yunus.service.OrderService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user; // user() post processor: isteği göndermeden önce kimlik ekleyen yapı
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// OrderController GÜVENLİK TESTLERİ (A6.1): "Slice Test" (dilim test) ile HTTP katmanının kapısı.
// Servisler doğrudan çağrılmaz; gerçek bir HTTP isteği gönderilir gibi controller test edilir.
// Slice Test: Veritabanı/JPA ayağa kaldırılmaz. Yalnızca web dilimi (Controller, Filter, Security vb.) yüklenir. Servisler sahtedir (mock).
@WebMvcTest(OrderController.class) // Yalnızca OrderController'ı ve web bileşenlerini yükler. Boot 4 paketi kullanır. Otomatik MockMvc hazırlar.
@Import({SecurityConfig.class, RestAccessDeniedHandler.class, RestAuthenticationEntryPoint.class}) // @WebMvcTest güvenlik ayarlarını otomatik taramaz. Gerçek kurallarımız için SecurityConfig ve 401/403 handler'larını elle alıyoruz. (JwtFilter'ı eklemiyoruz, Spring Filter olduğu için kendi yükler).
@DisplayName("OrderController güvenliği")
class OrderControllerSecurityTest {

    private static final Long KULLANICI_ID = 1L;
    private static final Long ADMIN_ID = 2L;

    @Autowired
    MockMvc mockMvc; // Gerçek ağ/sunucu olmadan HTTP isteğini taklit eder. Filtre zinciri, güvenlik, controller ve exception handler'dan GERÇEKTEN geçer.

    // @MockitoBean: Spring bağlamındaki bean yerine Mockito sahtesi koyar ( Boot 4 karşılığı ). Her testten sonra sıfırlanır.
    @MockitoBean
    OrderService orderService; // Controller'ın bağımlılığı (İş mantığı sahte)

    @MockitoBean
    JwtService jwtService; // JwtFilter yapıcısında ister. Token kullanmasak da filtre yüklendiği için bağlamda bulunması şart.

    @MockitoBean
    CustomUserDetailsService customUserDetailsService; // JwtFilter için bağlamda bulunması gereken sahte bean.

    // Giriş yapmış kullanıcılar: gerçek UserPrincipal (ROLE_USER / ROLE_ADMIN yetkisiyle)
    // .with(user(userPrincipal)) yöntemi ile Controller'daki @AuthenticationPrincipal UserPrincipal parametresine tam uyar.
    private final UserPrincipal kullanici = principal(KULLANICI_ID, Role.USER);
    private final UserPrincipal admin = principal(ADMIN_ID, Role.ADMIN);

    private static UserPrincipal principal(Long id, Role rol) {
        return new UserPrincipal(User.builder()
                .id(id)
                .username("kullanici-" + id)
                .role(rol)
                .build());
    }

    // ==================================================================================
    // 1) ANONİM → 401 (Giriş yapmamış kullanıcı hiçbir sipariş ucuna giremiyor)
    // ==================================================================================
    @ParameterizedTest(name = "anonim: {0} {1} → 401")
    @CsvSource({ // CsvSource: "HTTP metodu, adres" çiftlerini tablo gibi verir.
            "POST,   /api/orders/create",
            "PATCH,  /api/orders/10/cancel",
            "GET,    /api/orders/get/10",
            "GET,    /api/orders/my",
            "GET,    /api/orders/user/5",
            "PATCH,  /api/orders/10/status?newStatus=SHIPPED",
            "GET,    /api/orders/all"
    })
    void anonim_tumUclarda401(String metot, String adres) throws Exception {
        // Kimlik bilgisi yok: istek filtre zincirinde durmalı, controller'a hiç ulaşmamalı
        mockMvc.perform(request(HttpMethod.valueOf(metot), adres)) // perform(): İsteği gönderir
                .andExpect(status().isUnauthorized()) // status().isUnauthorized() = 401 kontrolü
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)); // Yanıt JSON mu?

        verifyNoInteractions(orderService);   // Servis çağrılmadı (Yetkisiz istek servise ulaşmaz)
    }

    // ==================================================================================
    // 2) USER → admin uçlarında 403 (USER rolündeki kullanıcı admin uçlarına giremiyor)
    // ==================================================================================
    // Not: Güvenlik kontrolü ile argüman çözme sırası: @PreAuthorize ÖNCE çalışır.
    // Ancak param çözümü de yapıldığı için 403 testlerinde adres/parametreler hep geçerli verilmelidir.
    @ParameterizedTest(name = "USER: {0} {1} → 403")
    @CsvSource({
            "GET,    /api/orders/user/5",
            "PATCH,  /api/orders/10/status?newStatus=SHIPPED",
            "GET,    /api/orders/all"
    })
    void user_adminUclarinda403(String metot, String adres) throws Exception {
        mockMvc.perform(request(HttpMethod.valueOf(metot), adres).with(user(kullanici))) // Real UserPrincipal nesnesiyle istek
                .andExpect(status().isForbidden()) // status().isForbidden() = 403 kontrolü
                .andExpect(jsonPath("$.status").value(403));   // GlobalExceptionHandler'ın döndürdüğü JSON alanı ($ = kök)

        verifyNoInteractions(orderService);   // Yetkisiz istek servise ulaşmadı
    }

    // ==================================================================================
    // 3) ADMIN → admin uçlarında 200 (ADMIN rolündeki kullanıcı admin uçlarına girebiliyor)
    // ==================================================================================
    @ParameterizedTest(name = "ADMIN: {0} {1} → 200")
    @CsvSource({
            "GET,    /api/orders/user/5",
            "PATCH,  /api/orders/10/status?newStatus=SHIPPED",
            "GET,    /api/orders/all"
    })
    void admin_adminUclarinda200(String metot, String adres) throws Exception {
        // Servis stub'lanmadı: null döner, controller 200 ve boş gövde verir. Burada yalnızca YETKİ soruluyor.
        mockMvc.perform(request(HttpMethod.valueOf(metot), adres).with(user(admin)))
                .andExpect(status().isOk()); // status().isOk() = 200 kontrolü
    }

    // ==================================================================================
    // 4) USER, kendi uçlarında: servis TOKEN'daki kullanıcıyla çağrılır (id istekten değil principal'dan)
    // ==================================================================================
    @Test
    @DisplayName("GET /my: sayfa sorgusu token'daki kullanıcının id'siyle yapılır")
    void my_tokenKullanicisiIdsiyleCagrilir() throws Exception {
        mockMvc.perform(get("/api/orders/my").with(user(kullanici)))
                .andExpect(status().isOk());

        // Kullanıcı id'si istekten değil principal'dan geliyor
        verify(orderService).getOrdersByUser(eq(KULLANICI_ID), any(Pageable.class));
    }

    @Test
    @DisplayName("GET /get/{id}: sipariş id'si yoldan, kullanıcı token'dan gelir; cevap JSON'a çevrilir")
    void getOrder_servisTokenKullanicisiylaCagrilir() throws Exception {
        // ARRANGE: servis hangi kullanıcıyla çağrılırsa çağrılsın bu cevabı versin
        OrderResponse cevap = OrderResponse.builder().id(10L).status(OrderStatus.PENDING).build();
        when(orderService.getOrderById(eq(10L), any(UserPrincipal.class))).thenReturn(cevap);

        // ACT + ASSERT: durum kodu ve JSON alanları
        mockMvc.perform(get("/api/orders/get/10").with(user(kullanici)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(10)) // jsonPath("$.id").value(10) -> JSON id alanı 10 mu?
                .andExpect(jsonPath("$.status").value("PENDING"));

        // Servise giden kullanıcı, kimlik olarak verdiğimiz AYNI nesne (same = aynı nesne referansı)
        verify(orderService).getOrderById(eq(10L), same(kullanici));
    }

    @Test
    @DisplayName("PATCH /{id}/cancel: iptal, token'daki kullanıcıyla istenir")
    void cancel_servisTokenKullanicisiylaCagrilir() throws Exception {
        mockMvc.perform(patch("/api/orders/10/cancel").with(user(kullanici)))
                .andExpect(status().isOk());

        verify(orderService).cancelOrder(eq(10L), same(kullanici));
    }

    @Test
    @DisplayName("POST /create: geçerli gövde → 201, gövde nesneye çevrilir, servis token kullanıcısıyla çağrılır")
    void create_gecerliGovde_201() throws Exception {
        // ARRANGE
        OrderResponse cevap = OrderResponse.builder().id(100L).status(OrderStatus.PENDING).build();
        when(orderService.createOrder(any(OrderRequest.class), any(UserPrincipal.class))).thenReturn(cevap);
        // CSRF SecurityConfig'te kapalı olduğu için POST/PATCH isteklerinde csrf() eklemiyoruz.
        String json = """
                {"items": [{"productId": 1, "quantity": 2}]}
                """;

        // ACT + ASSERT (1): 201 Created (isCreated) ve cevap JSON'u
        mockMvc.perform(post("/api/orders/create")
                        .with(user(kullanici))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(100));

        // ASSERT (2): JSON, OrderRequest nesnesine doğru çevrildi ve kullanıcı token'dan geldi
        ArgumentCaptor<OrderRequest> istekCaptor = ArgumentCaptor.forClass(OrderRequest.class);
        verify(orderService).createOrder(istekCaptor.capture(), same(kullanici));
        OrderRequest istek = istekCaptor.getValue();
        assertThat(istek.getItems()).hasSize(1);
        assertThat(istek.getItems().get(0).getProductId()).isEqualTo(1L);
        assertThat(istek.getItems().get(0).getQuantity()).isEqualTo(2);
    }

    
}