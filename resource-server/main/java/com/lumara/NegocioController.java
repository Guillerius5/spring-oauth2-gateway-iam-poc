package com.lumara.negocio;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class NegocioController {

    @GetMapping("/saludo")
    public String saludoGeneral(@AuthenticationPrincipal Jwt jwt) {
        return "Hola! Tu Token es válido y dice que tus roles son: " + jwt.getClaimAsStringList("roles");
    }

    @PreAuthorize("hasAuthority('ROLE_USER')") 
    @GetMapping("/admin")
    public String zonaVip() {
        return "¡Bienvenido a la zona VIP de Gestión! Como tienes el rol correcto, puedes leer esto.";
    }
}