package com.whizzy.rentcloud.profileservice.service;

import com.whizzy.rentcloud.commons.model.Vehicle;
import com.whizzy.rentcloud.profileservice.repository.VehicleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VehicleServiceImpl implements VehicleService{

    @Autowired
    private VehicleRepository vehicleRepository;

    @Override
    public Vehicle save(Vehicle vehicle) {
        return vehicleRepository.save(vehicle);
    }

    @Override
    public Vehicle fetchById(int id) {
        return vehicleRepository.findById(id).orElseThrow();
    }

    @Override
    public List<Vehicle> fetchAllVehicles() {
        return vehicleRepository.findAll();
    }
}
