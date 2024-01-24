package com.whizzy.rentcloud.profileservice.controller;

import com.whizzy.rentcloud.commons.model.Customer;
import com.whizzy.rentcloud.profileservice.service.CustomerService;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(value = "/services")
public class ProfileController {

    @Autowired
    private CustomerService customerService;

    @PostMapping(value = "/profile")
    @PreAuthorize("hasAuthority('SCOPE_CREATE_PROFILE')")
    public Customer save(@RequestBody Customer customer) {
        return customerService.save(customer);
    }

    @GetMapping(value = "/profile/{id}")
    public Customer fetchCustomer(@PathVariable("id") int customerId) {
        return customerService.fetchById(customerId);
    }

    @GetMapping(value = "/profiles")
    @PreAuthorize("hasAuthority('SCOPE_CREATE_PROFILE')")
    public List<Customer> fetchAll() {
        return customerService.fetchAllProfiles();
    }

    @GetMapping(value = "/profiles1")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public List<Customer> fetchAll1() {
        return customerService.fetchAllProfiles();
    }

    @GetMapping(value = "/profiles2")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Customer> fetchAll2() {
        return customerService.fetchAllProfiles();
    }

    @GetMapping(value = "/profiles3")
    @RolesAllowed("ADMIN")
    public List<Customer> fetchAll3() {
        return customerService.fetchAllProfiles();
    }

    @GetMapping(value = "/profiles4")
    @RolesAllowed("ROLE_ADMIN")
    public List<Customer> fetchAll4() {
        return customerService.fetchAllProfiles();
    }

}
