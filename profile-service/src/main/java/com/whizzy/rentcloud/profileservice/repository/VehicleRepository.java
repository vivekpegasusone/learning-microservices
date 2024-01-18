package com.whizzy.rentcloud.profileservice.repository;

import com.whizzy.rentcloud.commons.model.Vehicle;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface VehicleRepository extends JpaRepository<Vehicle, Integer> {
}
