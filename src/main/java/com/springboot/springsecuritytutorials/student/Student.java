package com.springboot.springsecuritytutorials.student;


import lombok.*;

import javax.persistence.Entity;
import javax.persistence.Id;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Student
{

    private Integer studentId;
    private String studentName;
}
