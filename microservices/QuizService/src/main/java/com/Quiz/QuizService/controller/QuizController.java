package com.Quiz.QuizService.controller;

import com.Quiz.QuizService.entities.Quiz;
import com.Quiz.QuizService.services.QuizService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/quiz")
public class QuizController {

   private QuizService quizService;

   public QuizController(QuizService quizService){
       this.quizService = quizService;
   }

   @PostMapping
   public Quiz create(@RequestBody Quiz quiz){
       return quizService.add(quiz);
   }

   @GetMapping
   public List<Quiz> get(){
       return quizService.get();
   }

    @GetMapping("/{id}")
    public Quiz getOne(@PathVariable Long id){
        return quizService.get(id);
    }
}
