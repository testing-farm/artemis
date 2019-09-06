from django.db import models
#from jsonschema import validate
import json, os

#TODO
#with open(os.path.join("PATH", "schema.json")) as f:
#    SCHEMA = json.loads(f)

class User(models.Model):
    id = models.IntegerField(primary_key=True)
    username = models.CharField(unique=True, max_length=200)

    def __str__(self):
        return self.username

class SSHKey(models.Model):
    id = models.IntegerField(primary_key=True)
    keyname = models.CharField(unique=True, max_length=200)
    enabled = models.BooleanField()
    owner = models.ForeignKey(User, default=None, related_name='keys', on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return "{}, {}".format(self.keyname, "enabled" if self.enabled else "disabled")

    @property
    def used_by(self):
        return self.guests.count()

class Priority(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=200)

    def __str__(self):
        return self.name

class Arch(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=200)

    def __str__(self):
        return self.name

class Compose(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=200)
    url = models.CharField(max_length=200)

    def __str__(self):
        return self.name

class Environment(models.Model):
    id = models.IntegerField(primary_key=True)
    arch = models.ForeignKey(Arch, related_name='environments', on_delete=models.CASCADE)
    compose = models.ForeignKey(Compose, related_name='environments', on_delete=models.CASCADE)

    def __str__(self):
        return 'Environment(arch={}, compose={}'.format(self.arch, self.compose)

    def __dict__(self):
        return {"arch":self.arch.name, "compose":{"name":self.compose.name, "url":self.compose.name}}

    #TODO: setter for arch as str and compose as str

class Guest(models.Model):
    id = models.IntegerField(primary_key=True)
    guestname = models.CharField(unique=True, max_length=200)
    key = models.ForeignKey(SSHKey, default=None, related_name='guests', on_delete=models.SET_NULL, null=True)
    owner = models.ForeignKey(User, default=None, related_name='guests', on_delete=models.SET_NULL, null=True)
    _priority = models.ForeignKey(Priority, default=None, related_name='guests', on_delete=models.SET_NULL, null=True)
    requested_environment = models.ForeignKey(Environment, related_name='actual_guests', on_delete=models.CASCADE)
    actual_environment = models.ForeignKey(Environment, default=None, related_name='requested_guests', on_delete=models.SET_NULL, null=True)
    # TODO: state (enum)
    # TODO: address (list of IPs)
    # TODO: ssh (object with username, port and key)

    def __str__(self):
        return self.guestname

    @property
    def keyname(self):
        return self.key.keyname

    @keyname.setter
    def keyname(self, value):
        self.key = SSHKey.objects.get(keyname=value)

    @property
    def priority(self):
        return self._priority.name

    @priority.setter
    def priority(self, value):
        self._priority = Priority.objects.get(name=value)

class Pool(models.Model):
    id = models.IntegerField(primary_key=True)
    poolname = models.CharField(unique=True, max_length=200)

    def __str__(self):
        return self.poolname