PGDMP                         {            MarketPlace    15.1    15.1 5    5           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            6           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            7           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            8           1262    16827    MarketPlace    DATABASE     �   CREATE DATABASE "MarketPlace" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'Russian_Russia.1251';
    DROP DATABASE "MarketPlace";
                postgres    false            �            1259    16829    category    TABLE     [   CREATE TABLE public.category (
    id integer NOT NULL,
    name character varying(255)
);
    DROP TABLE public.category;
       public         heap    postgres    false            �            1259    16828    category_id_seq    SEQUENCE     �   CREATE SEQUENCE public.category_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.category_id_seq;
       public          postgres    false    215            9           0    0    category_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.category_id_seq OWNED BY public.category.id;
          public          postgres    false    214            �            1259    16836    image    TABLE     ~   CREATE TABLE public.image (
    id integer NOT NULL,
    file_name character varying(255),
    product_id integer NOT NULL
);
    DROP TABLE public.image;
       public         heap    postgres    false            �            1259    16835    image_id_seq    SEQUENCE     �   CREATE SEQUENCE public.image_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.image_id_seq;
       public          postgres    false    217            :           0    0    image_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.image_id_seq OWNED BY public.image.id;
          public          postgres    false    216            �            1259    16892    orders    TABLE       CREATE TABLE public.orders (
    id integer NOT NULL,
    count integer NOT NULL,
    date_time timestamp(6) without time zone,
    number character varying(255),
    price real NOT NULL,
    status smallint,
    person_id integer NOT NULL,
    product_id integer NOT NULL
);
    DROP TABLE public.orders;
       public         heap    postgres    false            �            1259    16891    orders_id_seq    SEQUENCE     �   CREATE SEQUENCE public.orders_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 $   DROP SEQUENCE public.orders_id_seq;
       public          postgres    false    225            ;           0    0    orders_id_seq    SEQUENCE OWNED BY     ?   ALTER SEQUENCE public.orders_id_seq OWNED BY public.orders.id;
          public          postgres    false    224            �            1259    16843    person    TABLE     �   CREATE TABLE public.person (
    id integer NOT NULL,
    login character varying(100),
    password character varying(255),
    role character varying(255)
);
    DROP TABLE public.person;
       public         heap    postgres    false            �            1259    16842    person_id_seq    SEQUENCE     �   CREATE SEQUENCE public.person_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 $   DROP SEQUENCE public.person_id_seq;
       public          postgres    false    219            <           0    0    person_id_seq    SEQUENCE OWNED BY     ?   ALTER SEQUENCE public.person_id_seq OWNED BY public.person.id;
          public          postgres    false    218            �            1259    16852    product    TABLE     �  CREATE TABLE public.product (
    id integer NOT NULL,
    date_time timestamp(6) without time zone,
    description text NOT NULL,
    price real NOT NULL,
    seller character varying(255) NOT NULL,
    title text NOT NULL,
    warehouse character varying(255) NOT NULL,
    category_id integer NOT NULL,
    CONSTRAINT product_price_check CHECK ((price >= (1)::double precision))
);
    DROP TABLE public.product;
       public         heap    postgres    false            �            1259    16875    product_cart    TABLE     m   CREATE TABLE public.product_cart (
    id integer NOT NULL,
    person_id integer,
    product_id integer
);
     DROP TABLE public.product_cart;
       public         heap    postgres    false            �            1259    16874    product_cart_id_seq    SEQUENCE     �   CREATE SEQUENCE public.product_cart_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE public.product_cart_id_seq;
       public          postgres    false    223            =           0    0    product_cart_id_seq    SEQUENCE OWNED BY     K   ALTER SEQUENCE public.product_cart_id_seq OWNED BY public.product_cart.id;
          public          postgres    false    222            �            1259    16851    product_id_seq    SEQUENCE     �   CREATE SEQUENCE public.product_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 %   DROP SEQUENCE public.product_id_seq;
       public          postgres    false    221            >           0    0    product_id_seq    SEQUENCE OWNED BY     A   ALTER SEQUENCE public.product_id_seq OWNED BY public.product.id;
          public          postgres    false    220            ~           2604    16832    category id    DEFAULT     j   ALTER TABLE ONLY public.category ALTER COLUMN id SET DEFAULT nextval('public.category_id_seq'::regclass);
 :   ALTER TABLE public.category ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    214    215    215                       2604    16839    image id    DEFAULT     d   ALTER TABLE ONLY public.image ALTER COLUMN id SET DEFAULT nextval('public.image_id_seq'::regclass);
 7   ALTER TABLE public.image ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    216    217    217            �           2604    16895 	   orders id    DEFAULT     f   ALTER TABLE ONLY public.orders ALTER COLUMN id SET DEFAULT nextval('public.orders_id_seq'::regclass);
 8   ALTER TABLE public.orders ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    224    225    225            �           2604    16846 	   person id    DEFAULT     f   ALTER TABLE ONLY public.person ALTER COLUMN id SET DEFAULT nextval('public.person_id_seq'::regclass);
 8   ALTER TABLE public.person ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    219    218    219            �           2604    16855 
   product id    DEFAULT     h   ALTER TABLE ONLY public.product ALTER COLUMN id SET DEFAULT nextval('public.product_id_seq'::regclass);
 9   ALTER TABLE public.product ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    221    220    221            �           2604    16878    product_cart id    DEFAULT     r   ALTER TABLE ONLY public.product_cart ALTER COLUMN id SET DEFAULT nextval('public.product_cart_id_seq'::regclass);
 >   ALTER TABLE public.product_cart ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    223    222    223            (          0    16829    category 
   TABLE DATA           ,   COPY public.category (id, name) FROM stdin;
    public          postgres    false    215   =;       *          0    16836    image 
   TABLE DATA           :   COPY public.image (id, file_name, product_id) FROM stdin;
    public          postgres    false    217   �;       2          0    16892    orders 
   TABLE DATA           d   COPY public.orders (id, count, date_time, number, price, status, person_id, product_id) FROM stdin;
    public          postgres    false    225   I@       ,          0    16843    person 
   TABLE DATA           ;   COPY public.person (id, login, password, role) FROM stdin;
    public          postgres    false    219   �@       .          0    16852    product 
   TABLE DATA           k   COPY public.product (id, date_time, description, price, seller, title, warehouse, category_id) FROM stdin;
    public          postgres    false    221   �A       0          0    16875    product_cart 
   TABLE DATA           A   COPY public.product_cart (id, person_id, product_id) FROM stdin;
    public          postgres    false    223   NV       ?           0    0    category_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.category_id_seq', 3, true);
          public          postgres    false    214            @           0    0    image_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.image_id_seq', 70, true);
          public          postgres    false    216            A           0    0    orders_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.orders_id_seq', 6, true);
          public          postgres    false    224            B           0    0    person_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.person_id_seq', 3, true);
          public          postgres    false    218            C           0    0    product_cart_id_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('public.product_cart_id_seq', 11, true);
          public          postgres    false    222            D           0    0    product_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.product_id_seq', 13, true);
          public          postgres    false    220            �           2606    16834    category category_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.category
    ADD CONSTRAINT category_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.category DROP CONSTRAINT category_pkey;
       public            postgres    false    215            �           2606    16841    image image_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.image
    ADD CONSTRAINT image_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.image DROP CONSTRAINT image_pkey;
       public            postgres    false    217            �           2606    16897    orders orders_pkey 
   CONSTRAINT     P   ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (id);
 <   ALTER TABLE ONLY public.orders DROP CONSTRAINT orders_pkey;
       public            postgres    false    225            �           2606    16850    person person_pkey 
   CONSTRAINT     P   ALTER TABLE ONLY public.person
    ADD CONSTRAINT person_pkey PRIMARY KEY (id);
 <   ALTER TABLE ONLY public.person DROP CONSTRAINT person_pkey;
       public            postgres    false    219            �           2606    16880    product_cart product_cart_pkey 
   CONSTRAINT     \   ALTER TABLE ONLY public.product_cart
    ADD CONSTRAINT product_cart_pkey PRIMARY KEY (id);
 H   ALTER TABLE ONLY public.product_cart DROP CONSTRAINT product_cart_pkey;
       public            postgres    false    223            �           2606    16860    product product_pkey 
   CONSTRAINT     R   ALTER TABLE ONLY public.product
    ADD CONSTRAINT product_pkey PRIMARY KEY (id);
 >   ALTER TABLE ONLY public.product DROP CONSTRAINT product_pkey;
       public            postgres    false    221            �           2606    16862 $   product uk_qka6vxqdy1dprtqnx9trdd47c 
   CONSTRAINT     `   ALTER TABLE ONLY public.product
    ADD CONSTRAINT uk_qka6vxqdy1dprtqnx9trdd47c UNIQUE (title);
 N   ALTER TABLE ONLY public.product DROP CONSTRAINT uk_qka6vxqdy1dprtqnx9trdd47c;
       public            postgres    false    221            �           2606    16898 "   orders fk1b0m4muwx1t377w9if3w6wwqn    FK CONSTRAINT     �   ALTER TABLE ONLY public.orders
    ADD CONSTRAINT fk1b0m4muwx1t377w9if3w6wwqn FOREIGN KEY (person_id) REFERENCES public.person(id);
 L   ALTER TABLE ONLY public.orders DROP CONSTRAINT fk1b0m4muwx1t377w9if3w6wwqn;
       public          postgres    false    219    225    3210            �           2606    16868 #   product fk1mtsbur82frn64de7balymq9s    FK CONSTRAINT     �   ALTER TABLE ONLY public.product
    ADD CONSTRAINT fk1mtsbur82frn64de7balymq9s FOREIGN KEY (category_id) REFERENCES public.category(id);
 M   ALTER TABLE ONLY public.product DROP CONSTRAINT fk1mtsbur82frn64de7balymq9s;
       public          postgres    false    215    3206    221            �           2606    16903 "   orders fk787ibr3guwp6xobrpbofnv7le    FK CONSTRAINT     �   ALTER TABLE ONLY public.orders
    ADD CONSTRAINT fk787ibr3guwp6xobrpbofnv7le FOREIGN KEY (product_id) REFERENCES public.product(id);
 L   ALTER TABLE ONLY public.orders DROP CONSTRAINT fk787ibr3guwp6xobrpbofnv7le;
       public          postgres    false    221    225    3212            �           2606    16863 !   image fkgpextbyee3uk9u6o2381m7ft1    FK CONSTRAINT     �   ALTER TABLE ONLY public.image
    ADD CONSTRAINT fkgpextbyee3uk9u6o2381m7ft1 FOREIGN KEY (product_id) REFERENCES public.product(id);
 K   ALTER TABLE ONLY public.image DROP CONSTRAINT fkgpextbyee3uk9u6o2381m7ft1;
       public          postgres    false    221    3212    217            �           2606    16886 (   product_cart fkhpnrxdy3jhujameyod08ilvvw    FK CONSTRAINT     �   ALTER TABLE ONLY public.product_cart
    ADD CONSTRAINT fkhpnrxdy3jhujameyod08ilvvw FOREIGN KEY (product_id) REFERENCES public.product(id);
 R   ALTER TABLE ONLY public.product_cart DROP CONSTRAINT fkhpnrxdy3jhujameyod08ilvvw;
       public          postgres    false    221    223    3212            �           2606    16881 (   product_cart fksgnkc1ko2i1o9yr2p63ysq3rn    FK CONSTRAINT     �   ALTER TABLE ONLY public.product_cart
    ADD CONSTRAINT fksgnkc1ko2i1o9yr2p63ysq3rn FOREIGN KEY (person_id) REFERENCES public.person(id);
 R   ALTER TABLE ONLY public.product_cart DROP CONSTRAINT fksgnkc1ko2i1o9yr2p63ysq3rn;
       public          postgres    false    223    3210    219            (   H   x�3�0����x��.#��.lr��\Ɯ&^��ta߅M6\�W 2�^l������1z\\\ u'�      *   �  x�=U��$9�U_����D�����q����ș�1�#���D��ӶӾ#�'_\�\t7��+�G~����DK��yD����̈́�Y'�6��l���/ފ��t��|�4�M�SY��mv~��%�u�t�F�L���[kU����G��ZF�g��@����H���V�~�����ǩ����E��i��W�<���O�i��A���(��i:o:�����K�^��u�+���l��\ک�-��K�,�r��k��h�RU�f���>�K�~�˙���@0i�;�~����gz�_��Kc�w���דf�J�n��elk���Q-��c��`�]��r���C^��C`3��;��_��3*UY�53��/�^2�-c�s�����XZb�ˠ���Z@s6�L�	��&����˪��z��UN�#P�1�zY%�����|�G[�d]l�6�U�_��۴77՗/�t����H;��L�C�H䈱���,;��njK�s��� ]��	����>�e�>SdP,wr���r%��\��������oÊ`����t`f׈ٶ�����ﯚ�1-���S�T̈g�k���@��XÔxO��,%�=�~���Э�e����2שC�ӭ���P�uCh�T�y����Zp���ъ�ƥ�X4��.3e�����K:������
7�K�������[�k����������|� I$�6�*�K��Y�*��	�5�ra�װ�2>K�9��_q�'s��8/��8�k�ד�5L�p~�&�ƪg�_�@\��F?����S�X��������s��0x^�w$޸�
C�1N�!�X�H�\���9�yR�@0�$ڌ�/���0�0.�?`�ޫQe$,��}����'WӉl�'{!��:I7̋��o�ߊ(���wa��rN�qƪ�����K[>�J�p�>��g>i���ؑ�]x��6
z�aKf��]mO�"�b�{��~i� ��;��<bTy��0o{�į"-_�QP��ȳ/�$�{�xx�+�p��0D���ޤ?c����+!�b	��$�}�F�υ�H��'����A>@��%��^�"��d�����g��c��R�d�Y�!{���	�:W�L��0�S�%m��E�v�@В'�.^��xյ<n�X�%m��>�Ͽ4�-      2   r   x�e̹! ��pb�!	j�DG�%��<�-`{������b��S�	�����25���i�Iʽ#�A�oSz���p��1���Q?t|�`u����/~rk�ow�Z��\!�      ,   �   x�M�Qn�0  �oz�Ѷ���m���f�R)�:��_��d� R5��0�4��<�.}Oz{	�仔�����z�4Ά:���e0���3�7�}��<�����C���78d��[�c�/�UTWև{�V��|�Y7q�AniT1z�����b�;���]
��<W������p��l�^r����f�6d"���׽Z ��I�      .      x��[K�$W�^�����+�RuS�~�,4t��l#!�f���0��p캪]�izf�n� _{���J �"���;�Y� ��E�9'5� d�+��yĉ��G[�N����u���I��;��v��n���1���|�'�iq�������W��D�N������p�>��Q���/��o����b����2��o�c����y��iD�N�4��<ɗ�PR�y�K�����|�/�OhTF���xL�f</�Ƭ4K��i���ni���̬��Y3Z��g?�	�MdŹM���Q�U�������Kza٤�D���^�D<�x����ogUL#�5ϳg���4�f�oX�X���O�kz�.�Ͳi<1ʯxG6��Ŵ�/��-O��#���!$,��]F�0$q׶Ev�[�!Hn紁kRjF#$�I�g��B��y��ڹ��#[���E��4� �\�9I<���1͖�l���O��6�:_ŋ��{��Ŭ��V� f&P5,���DK6z���J4����Ue�ޖ~Cݮ�<c�Ғ��
���\K��r��9-tF�@3�#�4���.Y����P,�/�j���ч^�i9D�>�vSV:�ղ��֗��;'�:א�|��@��Z�Y#^�F��K����Ս�X�L����	]���}ɮ�ֱ�j8����4	.1����N����q�X�ϙZ
�8��D�[ho��Ў��Q��+�/�,�q��RH� NA��ĂK�!n�1��a[Q���U��_�kг�ib�>Ɋ5A�nD�D� X!�n�ґ�̺�����&�آ|��p�����gZ	���옎Δ���N��?g��m���#��c�e�,y��%<�>���H�k'����<'#�r7����3A"y���;��ʣ��`��3�tz-��=��J���
%�)��xo8*��]�l7eK����U�A/�@�z�����ܨ|�w��s�8�1��o�M`�;�/���aU�Q����tO��z�."T�! �
��K�
]� 3�j��!t`��oa�d������U���.½d�Ǡ��U�ܒ�Hu�ۺ�����DhC;}ԍ�@�s�N�������6c�6�u]x��?�~hY�[Z�N����O�,b2�bj���t
���2���
��ğ�eIn	���v
{؈��2Dݕ ��\���K��@,7��u���o���ί�`X:�nA���Au�����b��X��x���Yq���v�����+��� \��dԁ����	�Y
d��l��dP�T���|��O�|Mj�z��q�SN�r�#����pX`1/�`=W�fM������R����[���^n�-�5�x�����Lo�W 
�����F�c�N���NLivV�sac!�b�T�pi�!��1��"-�'��^
Qt2.ӎ1�e��w-v���Z+���Ȋ�8O���|&��`62��QB����5�y�������ԁ	N�y��A?�'@�
���$�za��y�9�~
O���kl'xH��{`%s0�.���b�i>iB��K��$N���X`�&���+�����B�8<��H���Vi3Y���}�undE�8��J0<u�e�
������K� n���~���?���1��XLC�52��eJ�5NtL"z���?��W�����3�bw�OM�c��3�!p��x��8�X�ud%�t$sn�����b?�)b�T�'۝�����g|^mC�ou�NK�M��/���{�
eۭ���d�$��VHb�s��������A+�_�=���\RE
�Yj[�U�>6^Y7�6��s�X�WFŢY3%�d7n��I��J���8.=�.<<��.ݲ�ˇ{��R/eL2��lb�0��pH�$C��YI�x�S\�C>D������$�����ge�(��v:�ɰ�O�ɿ�q�u�:��!�r@}t�ڲ)Y�!JZ�ؚl*9%I�T���*f<+�XN��b)�s�X���"�?W�����$U���M�Rs?��O�`�-�FY'�3��܅�L�t!�#c0ɸ�^�m���O��-:�$��W�)W��� ��{�4=$�2�J����D�3��x��J��pmV^���#qz@������K������!�M�#���%�6�#�yi����gt�X��R5���[/�������B��M�	&����L�3e:O����w��9��=3˖�`)�:+��EtB�>Bl���sgAf��"�iB
9!�R�$��$1R��]�;U�T[���!S��3M���Yz�����dZ�5��S����2��xϒ?V9h*&%�m��IC{�k�6��D�M�]��x���oU.,��2��Y(�����a��QL�׳�P�����Z�g��JJ�� � �9��HSM++>,`	�$�*�'� Xڙ�H��_�2	��?����8�������Z?��O?��/?����[(Bq9���I��<8>�Zo~���_���]��R��͗���fGV3��|�[}-r�-��_�G�ngЎ^y������j��9>>n�W�����g�����>�ݿ|�0�����4�'��~�w08l���+3�7��)��&�]�ʮG���V� cu���k�a��5�%�/��|��?Ⱦ�5�X����F�f�����2���n;R�k�c��;K���8;�e����E�k�x�sv;��ޕ1\�9����.�X��*�u}��_NIW�*����bi�h�����,x��=��
�
|=��U1f�az9*�B|�4����Vk���L��$��r�1NHa�U\\���K)��$��ҙ��mM5�B��)���ׂ�9���0�+�4���(7cd�3N�����o����7ך��E\�d?p��%�ԛ��2P{�Mߥ@v����*����4U�5(2�M��(���h���m��I���T-fХ[�p��m9��~S ��t΍gA2���ңE0�5^�N�:77���Z�Z�=,��c�{x|<l�Ϭ�U8��7��~�����{��x3U��I��ւo��[��������p��Z�` w�Ҕ�sy����;Z������������y��wB�0�z��!�|��U:�Z��,�Ц����c �fR��@ucS�$��{R�4���F�����`�J�89��WKʢ���Χ �(�3�6N��֠��`��)J�z���O�*�IQ��؆�Z/x��ʢI�U�o�Ӆ%4�2�cxא�g�,�ڠ>�s^܅�q:��m_�V�ʹ7����L�4���	�^���I�lOJ]�% >��D�LJw�x��qK�W�Us� 7"�7�2�^$��rk˨t9`:�"u�UQTR��5��]y��o��	Ĥ�M@"�{�䥷�kI��Uk�Ҟ�;t�p�*�ĉ����P �B��"șH�ۖP�Da蟙h�8a$d�q�UC�]��Z2w���Yt��ش��d�^�f�}����N�ݨ���:�&�<j��VPf�F�~�%�.㐡���/����u[�N����R
��ޗ�J�(	6-��5�/�Wp\Z�`�w�{-�&q1�]��Za۔�l�јK�Ru�$c�x�-}��zd�T��H��U�U���n�7�K=x��w<� I��)�^_��w�)&�!���(�Jל����!"ώ�[j^Ԛ��.�Z��k��������H��;���S�F)�ӳ\��d�-��Y���u�ޥά�nm$&��<|�!�������Ehk�3z�}�A�qAR|��3Oj�RI��������.h�z"q��e�fw`�2.$7b�"z�d"f�$i"$��0mQ�i�U��{�ٜ�+��`ج�\>��)�M�҇fW�츚Kڜ�瑔��<_�l��;n�|a����H���1j��r�^[+I���֢�RCT%}h	�)��,�ો���H0z��9r��xs����2�#?e��5� ������#�C�=X�|G��KY��\�)�G�i*����$�<`���'Ը�|�6�m4HH���������asm�-n �  ��Z�����tZ��8+�FA2$<�1�F0*MT��r)�g�nܭqm��E��d�w�nhE��7i�(��T=R�&�&�R�366%$Y�:��&ch�N��B0i�Hq߾�z�5�^�ڑj����c���K�5���ا��v�i*Gnh̼�_И��ؾ�����.IoU���;�� ��ɿ��3�?��Zh�{���s�W������,�m.<P����5����DR� ���ρ)�r�ؒ�x���`�;��t�7ʳ���a���B��U_#��?>����[�a��S۰w�謕�q��ZW¦v�n�%^zQ�s��r�����Q��L*�� �����a�WL�P$c�"pfu��^���M΅��!K��Bn���`v)'r=n����,i �Z��Ƙu-o&a�|a3Ar��~3�j�TibZ�%ˉ�>�)A��r��X�Q�,8��-�4v�ܥ�qTֺ���]�Y5m�?�q�RXҩ.kW�yg�0�{Mn^�A��ped"��S$+7&m�Ѱѵw	������X��ՙ�ȅ! c����_@�ga��X�(m��d�˕�.�����K�:����|ղ�G�#/̫�Dz��x����×Y�%���T?�@�*0<\д�Bh�1;�2�N7�]���D޶R�n4�A�(q?V��#�V��O�����O��)�EE�}n6���f�x��M5L~I��i�a��$h��ȭq�;2�D��S-����wX�V��C���x�M~E�|Z�h�hǽ��2h���Q�1�X�{���z����u�h�ƅ"����Aݙ�;/�ډS��:eJ���iv�]��u-�X��~�#Q$Y)(~�,�Srn��ݭ��r�ڟ9�c"]��Y�-�;x�q��o�$��$V1 hrZ8�MШ|9��vɲ���Pw�}!��8:����A2c��T��)|*<�dz�0tg��
͟H )֤�%��������X��}�F��Ԕ�̎�Ōo��y�~8#t�5oţ�"hB��v�h�g"�����[(T�\Bl���7lA���p+��&�\9<���]aJ|c�[���G�R�n� �5��׺$t��'Q�g?+��^f-"��(���Ӗ'�	��A�=�`N��p���&�IG5����{��`���      0      x������ � �     