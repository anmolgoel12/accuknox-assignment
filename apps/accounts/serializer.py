from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework import serializers

from .models import ConnectionLog, Connections

User = get_user_model()


class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("email", "name", "password")
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        email = validated_data.pop("email")
        password = validated_data.pop("password")
        group = Group.objects.get(pk=(self.context["request"]).data.get("role", 1))
        user = User.objects.create_user(
            email=email.lower(), password=password, **validated_data
        )
        user.groups.add(group)
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
        extra_kwargs = {"password": {"write_only": True}}


class UserSearchSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "name", "email"]


class ConnectionSentSerializer(serializers.ModelSerializer):
    to_user = UserSearchSerializer()

    class Meta:
        model = Connections
        fields = "__all__"


class ConnectionInvitationSerializer(serializers.ModelSerializer):
    from_user = UserSearchSerializer()

    class Meta:
        model = Connections
        fields = "__all__"


class ConnectionLogSerializer(serializers.ModelSerializer):

    class Meta:
        model = ConnectionLog
        fields = "__all__"
