from django.db import models

class usuario(models.Model):
    
    def __str__ (self):
        return self.nome
