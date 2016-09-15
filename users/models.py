from django.contrib.auth.models import AbstractUser
from django.db import models
from oauth2client.contrib.django_util.models import CredentialsField
from django.contrib import admin
from django.contrib.auth.models import User


# class CustomUser(AbstractUser):
#     social_thumb = models.URLField(null=True, blank=True)


class CredentialsModel(models.Model):
	id = models.ForeignKey(User, primary_key=True)
	credential = CredentialsField()

class CredentialsAdmin(admin.ModelAdmin):
    pass


admin.site.register(CredentialsModel, CredentialsAdmin)
# admin.site.register(CustomUser)