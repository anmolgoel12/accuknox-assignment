from django.db.models import Q
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from rest_framework.viewsets import ModelViewSet

from accuknox.utils import custom_success_response, update_object_response

from .models import *
from .serializer import (
    ConnectionInvitationSerializer,
    ConnectionSentSerializer,
    CreateUserSerializer,
    UserSearchSerializer,
    UserSerializer,
)

"""
User Sing-up process
required field: email,name, password
"""


class UserViewSet(ModelViewSet):
    queryset = User.objects.all()

    def get_serializer_class(self, *args, **kwargs):
        method = self.request.method.lower()
        return UserSerializer if method in ("get", "delete") else CreateUserSerializer

    def create(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return custom_success_response(serializer.data, status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        search = request.query_params.get("search", None)
        users = User.objects.filter(Q(email=search) | Q(name__icontains=search))
        return custom_success_response(UserSearchSerializer(users, many=True).data)

    @action(
        detail=False,
        methods=["get"],
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def my_account(self, request):
        return custom_success_response(self.get_serializer(request.user).data)


"""
User Sing-in process
required field: username['email'], password
"""


class Login(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data["user"]
            token, created = Token.objects.get_or_create(user=user)

            return custom_success_response(
                {
                    "token": token.key,
                    "user_id": user.pk,
                    "email": user.email,
                    "name": user.name,
                }
            )


class ConnectionsViewSet(ModelViewSet):
    queryset = Connections.objects.all()
    serializer_class = UserSearchSerializer
    permission_classes = [IsAuthenticated]

    def list(self, request):
        """
        List all friends
        """
        friend_list = Connections.objects.filter(
            Q(from_user=request.user) | Q(to_user=request.user)
        ).filter(state=True)

        serializer = ConnectionInvitationSerializer(friend_list, many=True)
        return custom_success_response(serializer.data)

    @action(
        detail=True,
        methods=["post"],
        permission_classes=[
            IsAuthenticated,
        ],
        throttle_classes=[
            UserRateThrottle
        ],  ## throttling being used restricted to 3 reqests / minute by User
    )
    def request(self, request, pk):
        """
        Sent friend request
        """
        from_user = request.user
        to_user = User.objects.get(pk=pk)
        if not Connections.objects.filter(
            from_user=from_user, to_user=to_user
        ).exists():
            if to_user == from_user:
                raise ValidationError({"message": ["Cannot send request to self"]})
            Connections.objects.get_or_create(from_user=from_user, to_user=to_user)
            return update_object_response(message="success, Request sent")
        else:
            raise ValidationError({"message": ["Invitation from the user exists"]})

    @action(
        detail=True,
        methods=["put"],
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def accept(self, request, pk=None):
        """
        Accept Friend Request
        """
        cr = self.get_object()
        if not cr.to_user_id == request.user.id:
            raise ValidationError(
                {"message": ["Request is not owned by Logged In user"]}
            )
        cr.state = True
        cr.save()
        return update_object_response(message="success, Request accepted")

    @action(
        detail=False,
        methods=["get"],
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def invitations(self, request, pk=None):
        """
        List all pending requests
        """
        conn_obj = Connections.objects.filter(to_user=request.user.id, state=None)
        serializer = ConnectionInvitationSerializer(conn_obj, many=True)
        return custom_success_response(serializer.data)

    @action(
        detail=False,
        methods=["get"],
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def sent(self, request, pk=None):
        """
        List all requests sent
        """
        conn_obj = Connections.objects.filter(from_user=request.user)
        serializer = ConnectionSentSerializer(conn_obj, many=True)
        return custom_success_response(serializer.data)

    @action(
        detail=True,
        methods=["delete"],
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def withdraw(self, request, pk=None):
        """
        Wthdraw a friends request only possible when no action taken by receiver yet
        """
        flag, _ = Connections.objects.filter(
            pk=pk, from_user=request.user, state=None
        ).delete()
        if flag:
            return update_object_response(
                message="success, Request withdrawn", status=status.HTTP_204_NO_CONTENT
            )
        raise ValidationError(
            {"message": ["Connection doesn't exists Or cannot be withdrawn"]}
        )

    @action(
        detail=True,
        methods=["put"],
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def ignore(self, request, pk=None):
        """
        Reject a request
        """
        if Connections.objects.filter(pk=pk, to_user=request.user).update(state=False):
            return update_object_response(message="success, Request ingnored")
        raise ValidationError(
            {"message": ["Connection doesn't exists Or you are not a owner of request"]}
        )
