package com.mak.oauth2_demo;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * FoodOrderingController handles web requests related to the home and menu pages of the food ordering application.
 */
@Controller
public class FoodOrderingController {

    /**
     * Maps the root URL ("/") to the home page.
     *
     * @return the name of the view to render for the home page
     */
    @GetMapping("/")
    public String home() {
        return "home";
    }

    /**
     * Maps the "/menu" URL to the menu page and sets the authenticated user's username in the model.
     *
     * @param user  the authenticated OIDC (OpenID Connect) user
     * @param model Model object for passing data to the view
     * @return the name of the view to render for the menu page, or redirects to home if user is not authenticated
     */
    @GetMapping("/menu")
    public String menu(@AuthenticationPrincipal OidcUser user, Model model) {
        if (user != null) {
            model.addAttribute("username", user.getPreferredUsername());
        } else {
            return "redirect:/";  // Redirect to home if not authenticated
        }
        return "menu";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }
}