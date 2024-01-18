package com.whizzy.rentcloud.profileservice.controller;

import com.whizzy.rentcloud.commons.model.Vehicle;
import com.whizzy.rentcloud.profileservice.service.VehicleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(value = "/services")
public class VehicleController {

    @Autowired
    private VehicleService vehicleService;

    @PostMapping(value = "/vehicle")
    public Vehicle save(@RequestBody Vehicle vehicle) {
        return vehicleService.save(vehicle);
    }

    @GetMapping(value = "/vehicle/{id}")
    public Vehicle fetchCustomer(@PathVariable("id") int vehicleId) {
        return vehicleService.fetchById(vehicleId);
    }

    @GetMapping(value = "/vehicles")
    public List<Vehicle> fetchAll() {
        return vehicleService.fetchAllVehicles();
    }

}
