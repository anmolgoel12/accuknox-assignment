import datetime

from django.core.cache import cache
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from yaml import serialize

from accuknox.permission import RBACPermission
from accuknox.utils import custom_success_response, update_object_response

from .models import *
from .serializer import (
    ConnectionInvitationSerializer,
    ConnectionLogSerializer,
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

    def get_permissions(self):
        method = self.request.method.lower()
        if method == "get":
            return [IsAuthenticated(), RBACPermission()]
        else:
            return []

    def create(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return custom_success_response(serializer.data, status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        search = request.query_params.get("search", None)
        users = User.objects.filter(Q(email=search) | Q(name__icontains=search))
        paginator = Paginator(users, 10)
        page_number = request.GET.get("page", 0)
        page_obj = paginator.get_page(page_number)
        return custom_success_response(
            UserSearchSerializer(page_obj, many=True).data,
            **{"current_number": page_number, "total_pages": paginator.num_pages},
        )

    @action(
        detail=False,
        methods=["get"],
        permission_classes=[IsAuthenticated, RBACPermission],
    )
    def my_account(self, request):
        return custom_success_response(self.get_serializer(request.user).data)


"""
User Sing-in process
required field: username['email'], password
"""


class Login(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        # email case insensitive
        data = {
            "email": request.data.get("email", None).lower(),
            "password": request.data.get("password", None),
        }
        serializer = TokenObtainPairSerializer(data=data, context={"request": request})
        if serializer.is_valid(raise_exception=True):
            user = User.objects.get(email=data["email"])
            return custom_success_response(
                {
                    "user_id": user.pk,
                    "email": user.email,
                    "name": user.name,
                    **serializer.validated_data,
                }
            )


class ConnectionsViewSet(ModelViewSet):
    queryset = Connections.objects.all()
    serializer_class = UserSearchSerializer
    permission_classes = [IsAuthenticated, RBACPermission]

    def list(self, request):
        """
        List all friends
        """
        friend_list = Connections.objects.filter(
            Q(from_user=request.user) | Q(to_user=request.user)
        ).filter(state=True)
        cache_key = f"friend_list_{request.user.id}"
        cached_data = cache.get(cache_key)
        if cached_data is not None:
            return custom_success_response(cached_data)  # Return cached data
        serializer = ConnectionInvitationSerializer(friend_list, many=True)
        cache.set(cache_key, serializer.data, timeout=60)  # Cache for 5 minutes
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
        Send friend request
        o	If a user rejects a friend request, the sender cannot send another request for a configurable cooldown period (e.g., 24 hours).
        o	Add a feature to block/unblock users, which prevents sending friend requests or viewing profiles
        """
        with transaction.atomic():
            from_user = request.user
            to_user = User.objects.get(pk=pk)
            if not Connections.objects.filter(
                from_user=from_user, to_user=to_user
            ).exists():
                if to_user == from_user:
                    raise ValidationError({"message": ["Cannot send request to self"]})
                connectionlog = ConnectionLog.objects.filter(
                    from_user=to_user,
                    to_user=from_user,
                    action__in=["reject", "blocked"],
                ).last()
                if connectionlog:
                    if (
                        connectionlog.action == "reject"
                        and connectionlog.date
                        > datetime.datetime.now() - datetime.timedelta(days=1)
                    ):
                        raise ValidationError(
                            {"message": ["Request from rejected within 24hours"]}
                        )
                    if connectionlog.action == "blocked":
                        raise ValidationError(
                            {
                                "message": [
                                    "User has blocked you. Connection request cant be sent"
                                ]
                            }
                        )
                Connections.objects.get_or_create(from_user=from_user, to_user=to_user)
                ConnectionLog.objects.create(
                    from_user=from_user, to_user=to_user, action="sent"
                )
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
        with transaction.atomic():
            cr = self.get_object()
            if not cr.to_user_id == request.user.id:
                raise ValidationError(
                    {"message": ["Request is not owned by Logged In user"]}
                )
            cr.state = True
            cr.save()
            ## Logginf connection Request
            ConnectionLog.objects.create(
                from_user=cr.to_user, to_user=cr.from_user, action="accept"
            )
            return update_object_response(message="success, Request accepted")

    def block(self, request, pk=None):
        """
        block Friend Request
        """
        with transaction.atomic():
            cr = self.get_object()
            if not cr.to_user_id == request.user.id:
                raise ValidationError(
                    {"message": ["Request is not owned by Logged In user"]}
                )
            cr.state = False
            cr.save()
            ## Logginf connection Request
            ConnectionLog.objects.create(
                from_user=cr.to_user, to_user=cr.from_user, action="blocked"
            )
            return update_object_response(message="success,User Request Blocked")

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
        o	Include pagination and sorting options (e.g., by the date of the request).
        """
        sort = request.query_params.get("date", 1)
        conn_obj = Connections.objects.filter(
            to_user=request.user.id, state=None
        ).order_by(f"{'-' if sort =='1' else ''}timestamp")
        paginator = Paginator(object_list=conn_obj, per_page=10)
        page_number = request.GET.get("page", 0)
        page_obj = paginator.get_page(page_number)
        serializer = ConnectionInvitationSerializer(page_obj, many=True)
        return custom_success_response(
            serializer.data,
            **{"current_number": page_number, "total_pages": paginator.num_pages},
        )

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


class ConnectionLogViewSet(ModelViewSet):
    queryset = ConnectionLog.objects.all()
    serializer_class = ConnectionLogSerializer
    permission_classes = [IsAuthenticated, RBACPermission]

    def list(self, request, *args, **kwargs):
        user = request.user
        log = ConnectionLog.objects.filter(from_user=user)
        serializer = self.get_serializer(log, many=True)
        return custom_success_response(serializer.data)
