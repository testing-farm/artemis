from django.core import exceptions
from rest_framework.response import Response
from rest_framework import viewsets
from api.models import *
from api.serializers import *
import random  #TODO: remove later

def handler401():
    return Response({"message":"Not authorized to perform this action"}, 401)

def handler403():
    return Response({"message": "Not authorized to perform this action"}, 403)

def handler404():
    return Response({"message": "No such entity"}, 404)

def handler409():
    return Response({ "message": "Object already exists."}, 409)

class UserViewSet(viewsets.ViewSet):
    """
    API endpoint that allows users to be created, viewed or edited.
    """
    # TODO: authentication and permission classes
    queryset = User.objects.all()

    def list(self, request):
        serializer = UserSerializer(User.objects.all(), many=True)
        return Response(serializer.data)

    def create(self, request):        
        username = self.request.data.get("username")

        # TODO replace with schema check
        if username is None:
            return Response({"message":"username field is required"}, 400)

        try:
            user = User(username=username)
            serializer = UserSerializer(user)
            serializer.create(serializer.data)
        except exceptions.ValidationError as e:
            return Response({"message":e.message}, e.code)
        
        return Response(None, 201)

    def retrieve(self, request, pk=None):
        # TODO replace with schema check
        if pk is None:
            return Response({"message":"username field is required"}, 400)

        try:
            user = User.objects.get(username=pk)
            serializer = UserSerializer(user)
            return Response(serializer.data)
        except User.DoesNotExist:
            return handler404()

    def partial_update(self, request, pk=None):

        # TODO replace with schema check
        username = self.request.data.get("username")

        if pk is None or username is None:
            return Response({"message":"username field is required"}, 400)

        try:
            user = User.objects.get(username=pk)
            user.username = username
            serializer = UserSerializer(user, partial=True)
            serializer.update(self.request.data)
        except User.DoesNotExist:
            return handler404()
        except exceptions.ValidationError as e:
            return Response({"message":e.message}, e.code)

        return Response(None)

    def destroy(self, request, pk=None):
        # TODO replace with schema check

        if pk is None:
            return Response({"message":"username field is required"}, 400)

        try:
            user = User.objects.get(username=pk)
            user.delete()
        except User.DoesNotExist:
            return handler404()

        return Response(None, 200)
    #TODO: inspect resource usage
    #TODO: inspect  create auth token


class SSHKeyViewSet(viewsets.ViewSet):
    """
    API endpoint that allows SSH keys to be created, viewed or edited.
    """
    # TODO: authentication and permission classes
    queryset = SSHKey.objects.all()

    def list(self, request):
        serializer = SSHKeySerializer(SSHKey.objects.all(), many=True)
        return Response(serializer.data)

    def create(self, request):
        keyname = self.request.data.get("keyname")
        enabled = self.request.data.get("enabled")

        # TODO replace with schema check
        if keyname is None:
            return Response({"message":"keyname field is required"}, 400)
        if enabled is None:
            return Response({"message":"enabled field is required"}, 400)

        try:
            key = SSHKey(keyname=keyname, enabled=enabled)
            serializer = SSHKeySerializer(key)
            serializer.create(serializer.data)
        except exceptions.ValidationError as e:
            return Response({"message":e.message}, e.code)
        
        return Response(None, 201)

    def retrieve(self, request, pk=None):
        # TODO replace with schema check
        if pk is None:
            return Response({"message":"username field is required"}, 400)

        try:
            key = SSHKey.objects.get(keyname=pk)
            serializer = SSHKeySerializer(key)
            return Response(serializer.data)
        except SSHKey.DoesNotExist:
            return handler404()

    def partial_update(self, request, pk=None):

        # TODO replace with schema check
        keyname = self.request.data.get("keyname")

        if pk is None or keyname is None:
            return Response({"message":"keyname field is required"}, 400)

        try:
            key = SSHKey.objects.get(keyname=pk)
            key.keyname = keyname
            serializer = SSHKeySerializer(key, partial=True)
            serializer.update(self.request.data)
        except SSHKey.DoesNotExist:
            return handler404()
        except exceptions.ValidationError as e:
            return Response({"message":e.message}, e.code)

        return Response(None)

    def destroy(self, request, pk=None):
        # TODO replace with schema check

        if pk is None:
            return Response({"message":"keyname field is required"}, 400)

        try:
            key = SSHKey.objects.get(keyname=pk)
            key.delete()
        except SSHKey.DoesNotExist:
            return handler404()

        return Response(None, 200)


class GuestViewSet(viewsets.ViewSet):
    """
    API endpoint that allows guests to be created, viewed or edited.
    """
    # TODO: authentication and permission classes
    queryset = Guest.objects.all()

    def list(self, request):
        serializer = GuestSerializer(Guest.objects.all(), many=True)
        return Response(serializer.data)

    def create(self, request):
        # TODO replace with schema check
        environment = self.request.data.get("environment")
        if environment is None:
            return Response({"message":"environment field is required"}, 400)

        compose = environment.get("compose")
        if compose is None:
            return Response({"message":"compose field is required"}, 400)

        arch = environment.get("arch")
        if arch is None:
            return Response({"message":"arch field is required"}, 400)

        priority = self.request.data.get("priority_group")
        if priority is None:
            return Response({"message":"priority_group field is required"}, 400)
    
        keyname = self.request.data.get("keyname")
        if keyname is None:
            return Response({"message":"keyname field is required"}, 400)

        #TODO: choose guest(name) from pool
        rand = str(random.random()).split('.')[1]

        try:
            arch = Arch.objects.get(name=arch)
            compose = Compose.objects.get(**compose)
            environment = Environment.objects.get(arch=arch, compose=compose)
            guest = Guest(guestname="guest{}".format(rand), requested_environment=environment, keyname=keyname, priority=priority)
            serializer = GuestSerializer(guest)
            serializer.create(serializer.data)
        except Arch.DoesNotExist:
            return Response({"message":"Unknown arch {}".format(arch)}, 400)
        except Compose.DoesNotExist:
            return Response({"message":"Unknown compose {} ({})".format(compose.get("name"), compose.get("url"))}, 400)
        except Environment.DoesNotExist:
            return Response({"message":"Unknown environment (arch={}, compose={})".format(arch, compose)}, 400)
        except SSHKey.DoesNotExist:
            return Response({"message":"Unknown SSH key {}".format(keyname)}, 400)
        except Priority.DoesNotExist:
            return Response({"message":"Unknown priority {}".format(priority)}, 400)
        except exceptions.ValidationError as e:
            return Response({"message":e.message}, e.code)

        #TODO: return reponse body 
        return Response(None, 201)

    def retrieve(self, request, pk=None):
        # TODO replace with schema check
        if pk is None:
            return Response({"message":"guestname field is required"}, 400)

        try:
            guest = Guest.objects.get(guestname=pk)
            serializer = GuestSerializer(guest)
            return Response(serializer.data)
        except Guest.DoesNotExist:
            return handler404()

    def partial_update(self, request, pk=None):

        # TODO replace with schema check
        guestname = self.request.data.get("guestname")

        if pk is None or guestname is None:
            return Response({"message":"guestname field is required"}, 400)

        try:
            guest = Guest.objects.get(guestname=pk)
            guest.guestname = guestname
            serializer = GuestSerializer(guest, partial=True)
            serializer.update(self.request.data)
        except Guest.DoesNotExist:
            return handler404()
        except exceptions.ValidationError as e:
            return Response({"message":e.message}, e.code)

        return Response(None)

    def destroy(self, request, pk=None):
        # TODO replace with schema check

        if pk is None:
            return Response({"message":"guestname field is required"}, 400)

        try:
            guest = Guest.objects.get(guestname=pk)
            guest.delete()
        except Guest.DoesNotExist:
            return handler404()

        return Response(None, 200)


class QueueViewSet(viewsets.ViewSet):
    """
    API endpoint that allows to inspect certain priority queue
    """
    # TODO: authentication and permission classes
    queryset = Priority.objects.all()

    def list(self, request):
        serializer = PrioritySerializer(Priority.objects.all(), many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        # TODO replace with schema check
        if pk is None:
            return Response({"message":"priority_group field is required"}, 400)

        try:
            priority = Priority.objects.get(name=pk)
            guests = Guest.objects.filter(_priority=priority)
            serializer = GuestSerializer(guests, many=True)
            return Response(serializer.data)
        except Priority.DoesNotExist:
            return handler404()
