from rest_framework import serializers
from django.core import exceptions
from api.models import *

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('username',)

    def validate_unique(self):
        try:
            User.objects.get(username=self.instance.username)
        except User.DoesNotExist:
            pass
        else:
            raise exceptions.ValidationError("Object already exists.", code=409)

    def create(self, validated_data):
        self.validate_unique()
        return User.objects.create(**validated_data)

    def update(self, validated_data):
        self.instance.username = validated_data.get("username", self.instance.username)
        self.validate_unique()
        self.instance.save()
        return self


class SSHKeySerializer(serializers.ModelSerializer):

    class Meta:
        model = SSHKey
        fields = ('keyname', 'enabled', 'owner', 'used_by')

    def validate_unique(self):
        try:
            SSHKey.objects.get(keyname=self.instance.keyname)
        except SSHKey.DoesNotExist:
            pass
        else:
            raise exceptions.ValidationError("Object already exists.", code=409)

    def create(self, validated_data):
        self.validate_unique()
        return SSHKey.objects.create(**validated_data)

    def update(self, validated_data):
        self.instance.keyname = validated_data.get("keyname", self.instance.keyname)
        self.validate_unique()
        self.instance.save()
        return self

class PrioritySerializer(serializers.ModelSerializer):

    class Meta:
        model = Priority
        fields = '__all__'

class ArchSerializer(serializers.ModelSerializer):

    class Meta:
        model = Arch
        fields = ('name',)

class ComposeSerializer(serializers.ModelSerializer):

    class Meta:
        model = Compose
        fields = ('name', 'url')

class EnvironmentSerializer(serializers.ModelSerializer):

    arch = serializers.StringRelatedField()
    compose = ComposeSerializer()

    class Meta:
        model = Environment
        fields = ('arch', 'compose')

class GuestSerializer(serializers.ModelSerializer):

    requested_environment = EnvironmentSerializer()

    class Meta:
        model = Guest
        fields = ('guestname', 'requested_environment', 'keyname', 'priority', 'owner')

    #TODO: validate

    def create(self, validated_data):
        environment = validated_data["requested_environment"]
        arch = Arch.objects.get(name=environment["arch"])
        compose = Compose.objects.get(**environment["compose"])
        environment = Environment.objects.get(arch=arch, compose=compose)
        keyname = validated_data["keyname"]
        priority = validated_data["priority"]
        guestname = validated_data["guestname"]
        return Guest.objects.create(guestname=guestname, requested_environment=environment,
                                    keyname=keyname, priority=priority)

class PoolSerializer(serializers.ModelSerializer):

    class Meta:
        model = Pool
        fields = '__all__'