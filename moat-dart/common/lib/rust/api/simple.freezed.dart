// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'simple.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

T _$identity<T>(T value) => value;

final _privateConstructorUsedError = UnsupportedError(
    'It seems like you constructed your class using `MyClass._()`. This constructor is only meant to be used by freezed and you are not supposed to need it nor use it.\nPlease check the documentation here for more information: https://github.com/rrousselGit/freezed#adding-getters-and-methods-to-our-models');

/// @nodoc
mixin _$PairingCommandDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $PairingCommandDtoCopyWith<$Res> {
  factory $PairingCommandDtoCopyWith(
          PairingCommandDto value, $Res Function(PairingCommandDto) then) =
      _$PairingCommandDtoCopyWithImpl<$Res, PairingCommandDto>;
}

/// @nodoc
class _$PairingCommandDtoCopyWithImpl<$Res, $Val extends PairingCommandDto>
    implements $PairingCommandDtoCopyWith<$Res> {
  _$PairingCommandDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$PairingCommandDto_SendFrameImplCopyWith<$Res> {
  factory _$$PairingCommandDto_SendFrameImplCopyWith(
          _$PairingCommandDto_SendFrameImpl value,
          $Res Function(_$PairingCommandDto_SendFrameImpl) then) =
      __$$PairingCommandDto_SendFrameImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List ciphertext});
}

/// @nodoc
class __$$PairingCommandDto_SendFrameImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_SendFrameImpl>
    implements _$$PairingCommandDto_SendFrameImplCopyWith<$Res> {
  __$$PairingCommandDto_SendFrameImplCopyWithImpl(
      _$PairingCommandDto_SendFrameImpl _value,
      $Res Function(_$PairingCommandDto_SendFrameImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? ciphertext = null,
  }) {
    return _then(_$PairingCommandDto_SendFrameImpl(
      ciphertext: null == ciphertext
          ? _value.ciphertext
          : ciphertext // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairingCommandDto_SendFrameImpl extends PairingCommandDto_SendFrame {
  const _$PairingCommandDto_SendFrameImpl({required this.ciphertext})
      : super._();

  @override
  final Uint8List ciphertext;

  @override
  String toString() {
    return 'PairingCommandDto.sendFrame(ciphertext: $ciphertext)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_SendFrameImpl &&
            const DeepCollectionEquality()
                .equals(other.ciphertext, ciphertext));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(ciphertext));

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_SendFrameImplCopyWith<_$PairingCommandDto_SendFrameImpl>
      get copyWith => __$$PairingCommandDto_SendFrameImplCopyWithImpl<
          _$PairingCommandDto_SendFrameImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return sendFrame(ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return sendFrame?.call(ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (sendFrame != null) {
      return sendFrame(ciphertext);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return sendFrame(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return sendFrame?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (sendFrame != null) {
      return sendFrame(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_SendFrame extends PairingCommandDto {
  const factory PairingCommandDto_SendFrame(
          {required final Uint8List ciphertext}) =
      _$PairingCommandDto_SendFrameImpl;
  const PairingCommandDto_SendFrame._() : super._();

  Uint8List get ciphertext;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_SendFrameImplCopyWith<_$PairingCommandDto_SendFrameImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_SeedKpPoolImplCopyWith<$Res> {
  factory _$$PairingCommandDto_SeedKpPoolImplCopyWith(
          _$PairingCommandDto_SeedKpPoolImpl value,
          $Res Function(_$PairingCommandDto_SeedKpPoolImpl) then) =
      __$$PairingCommandDto_SeedKpPoolImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List deviceId, List<OfferedKpDto> kps});
}

/// @nodoc
class __$$PairingCommandDto_SeedKpPoolImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_SeedKpPoolImpl>
    implements _$$PairingCommandDto_SeedKpPoolImplCopyWith<$Res> {
  __$$PairingCommandDto_SeedKpPoolImplCopyWithImpl(
      _$PairingCommandDto_SeedKpPoolImpl _value,
      $Res Function(_$PairingCommandDto_SeedKpPoolImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? deviceId = null,
    Object? kps = null,
  }) {
    return _then(_$PairingCommandDto_SeedKpPoolImpl(
      deviceId: null == deviceId
          ? _value.deviceId
          : deviceId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      kps: null == kps
          ? _value._kps
          : kps // ignore: cast_nullable_to_non_nullable
              as List<OfferedKpDto>,
    ));
  }
}

/// @nodoc

class _$PairingCommandDto_SeedKpPoolImpl extends PairingCommandDto_SeedKpPool {
  const _$PairingCommandDto_SeedKpPoolImpl(
      {required this.deviceId, required final List<OfferedKpDto> kps})
      : _kps = kps,
        super._();

  @override
  final Uint8List deviceId;
  final List<OfferedKpDto> _kps;
  @override
  List<OfferedKpDto> get kps {
    if (_kps is EqualUnmodifiableListView) return _kps;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_kps);
  }

  @override
  String toString() {
    return 'PairingCommandDto.seedKpPool(deviceId: $deviceId, kps: $kps)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_SeedKpPoolImpl &&
            const DeepCollectionEquality().equals(other.deviceId, deviceId) &&
            const DeepCollectionEquality().equals(other._kps, _kps));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType,
      const DeepCollectionEquality().hash(deviceId),
      const DeepCollectionEquality().hash(_kps));

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_SeedKpPoolImplCopyWith<
          _$PairingCommandDto_SeedKpPoolImpl>
      get copyWith => __$$PairingCommandDto_SeedKpPoolImplCopyWithImpl<
          _$PairingCommandDto_SeedKpPoolImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return seedKpPool(deviceId, kps);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return seedKpPool?.call(deviceId, kps);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (seedKpPool != null) {
      return seedKpPool(deviceId, kps);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return seedKpPool(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return seedKpPool?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (seedKpPool != null) {
      return seedKpPool(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_SeedKpPool extends PairingCommandDto {
  const factory PairingCommandDto_SeedKpPool(
          {required final Uint8List deviceId,
          required final List<OfferedKpDto> kps}) =
      _$PairingCommandDto_SeedKpPoolImpl;
  const PairingCommandDto_SeedKpPool._() : super._();

  Uint8List get deviceId;
  List<OfferedKpDto> get kps;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_SeedKpPoolImplCopyWith<
          _$PairingCommandDto_SeedKpPoolImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_PublishRingCommitImplCopyWith<$Res> {
  factory _$$PairingCommandDto_PublishRingCommitImplCopyWith(
          _$PairingCommandDto_PublishRingCommitImpl value,
          $Res Function(_$PairingCommandDto_PublishRingCommitImpl) then) =
      __$$PairingCommandDto_PublishRingCommitImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List tag, Uint8List ciphertext});
}

/// @nodoc
class __$$PairingCommandDto_PublishRingCommitImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_PublishRingCommitImpl>
    implements _$$PairingCommandDto_PublishRingCommitImplCopyWith<$Res> {
  __$$PairingCommandDto_PublishRingCommitImplCopyWithImpl(
      _$PairingCommandDto_PublishRingCommitImpl _value,
      $Res Function(_$PairingCommandDto_PublishRingCommitImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? tag = null,
    Object? ciphertext = null,
  }) {
    return _then(_$PairingCommandDto_PublishRingCommitImpl(
      tag: null == tag
          ? _value.tag
          : tag // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      ciphertext: null == ciphertext
          ? _value.ciphertext
          : ciphertext // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairingCommandDto_PublishRingCommitImpl
    extends PairingCommandDto_PublishRingCommit {
  const _$PairingCommandDto_PublishRingCommitImpl(
      {required this.tag, required this.ciphertext})
      : super._();

  @override
  final Uint8List tag;
  @override
  final Uint8List ciphertext;

  @override
  String toString() {
    return 'PairingCommandDto.publishRingCommit(tag: $tag, ciphertext: $ciphertext)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_PublishRingCommitImpl &&
            const DeepCollectionEquality().equals(other.tag, tag) &&
            const DeepCollectionEquality()
                .equals(other.ciphertext, ciphertext));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType,
      const DeepCollectionEquality().hash(tag),
      const DeepCollectionEquality().hash(ciphertext));

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_PublishRingCommitImplCopyWith<
          _$PairingCommandDto_PublishRingCommitImpl>
      get copyWith => __$$PairingCommandDto_PublishRingCommitImplCopyWithImpl<
          _$PairingCommandDto_PublishRingCommitImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return publishRingCommit(tag, ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return publishRingCommit?.call(tag, ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (publishRingCommit != null) {
      return publishRingCommit(tag, ciphertext);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return publishRingCommit(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return publishRingCommit?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (publishRingCommit != null) {
      return publishRingCommit(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_PublishRingCommit extends PairingCommandDto {
  const factory PairingCommandDto_PublishRingCommit(
          {required final Uint8List tag, required final Uint8List ciphertext}) =
      _$PairingCommandDto_PublishRingCommitImpl;
  const PairingCommandDto_PublishRingCommit._() : super._();

  Uint8List get tag;
  Uint8List get ciphertext;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_PublishRingCommitImplCopyWith<
          _$PairingCommandDto_PublishRingCommitImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_SurfaceApprovalPromptImplCopyWith<$Res> {
  factory _$$PairingCommandDto_SurfaceApprovalPromptImplCopyWith(
          _$PairingCommandDto_SurfaceApprovalPromptImpl value,
          $Res Function(_$PairingCommandDto_SurfaceApprovalPromptImpl) then) =
      __$$PairingCommandDto_SurfaceApprovalPromptImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String deviceName, String did});
}

/// @nodoc
class __$$PairingCommandDto_SurfaceApprovalPromptImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_SurfaceApprovalPromptImpl>
    implements _$$PairingCommandDto_SurfaceApprovalPromptImplCopyWith<$Res> {
  __$$PairingCommandDto_SurfaceApprovalPromptImplCopyWithImpl(
      _$PairingCommandDto_SurfaceApprovalPromptImpl _value,
      $Res Function(_$PairingCommandDto_SurfaceApprovalPromptImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? deviceName = null,
    Object? did = null,
  }) {
    return _then(_$PairingCommandDto_SurfaceApprovalPromptImpl(
      deviceName: null == deviceName
          ? _value.deviceName
          : deviceName // ignore: cast_nullable_to_non_nullable
              as String,
      did: null == did
          ? _value.did
          : did // ignore: cast_nullable_to_non_nullable
              as String,
    ));
  }
}

/// @nodoc

class _$PairingCommandDto_SurfaceApprovalPromptImpl
    extends PairingCommandDto_SurfaceApprovalPrompt {
  const _$PairingCommandDto_SurfaceApprovalPromptImpl(
      {required this.deviceName, required this.did})
      : super._();

  @override
  final String deviceName;
  @override
  final String did;

  @override
  String toString() {
    return 'PairingCommandDto.surfaceApprovalPrompt(deviceName: $deviceName, did: $did)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_SurfaceApprovalPromptImpl &&
            (identical(other.deviceName, deviceName) ||
                other.deviceName == deviceName) &&
            (identical(other.did, did) || other.did == did));
  }

  @override
  int get hashCode => Object.hash(runtimeType, deviceName, did);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_SurfaceApprovalPromptImplCopyWith<
          _$PairingCommandDto_SurfaceApprovalPromptImpl>
      get copyWith =>
          __$$PairingCommandDto_SurfaceApprovalPromptImplCopyWithImpl<
              _$PairingCommandDto_SurfaceApprovalPromptImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return surfaceApprovalPrompt(deviceName, did);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return surfaceApprovalPrompt?.call(deviceName, did);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (surfaceApprovalPrompt != null) {
      return surfaceApprovalPrompt(deviceName, did);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return surfaceApprovalPrompt(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return surfaceApprovalPrompt?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (surfaceApprovalPrompt != null) {
      return surfaceApprovalPrompt(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_SurfaceApprovalPrompt
    extends PairingCommandDto {
  const factory PairingCommandDto_SurfaceApprovalPrompt(
          {required final String deviceName, required final String did}) =
      _$PairingCommandDto_SurfaceApprovalPromptImpl;
  const PairingCommandDto_SurfaceApprovalPrompt._() : super._();

  String get deviceName;
  String get did;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_SurfaceApprovalPromptImplCopyWith<
          _$PairingCommandDto_SurfaceApprovalPromptImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_PersistRingImplCopyWith<$Res> {
  factory _$$PairingCommandDto_PersistRingImplCopyWith(
          _$PairingCommandDto_PersistRingImpl value,
          $Res Function(_$PairingCommandDto_PersistRingImpl) then) =
      __$$PairingCommandDto_PersistRingImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List ringId});
}

/// @nodoc
class __$$PairingCommandDto_PersistRingImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_PersistRingImpl>
    implements _$$PairingCommandDto_PersistRingImplCopyWith<$Res> {
  __$$PairingCommandDto_PersistRingImplCopyWithImpl(
      _$PairingCommandDto_PersistRingImpl _value,
      $Res Function(_$PairingCommandDto_PersistRingImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? ringId = null,
  }) {
    return _then(_$PairingCommandDto_PersistRingImpl(
      ringId: null == ringId
          ? _value.ringId
          : ringId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairingCommandDto_PersistRingImpl
    extends PairingCommandDto_PersistRing {
  const _$PairingCommandDto_PersistRingImpl({required this.ringId}) : super._();

  @override
  final Uint8List ringId;

  @override
  String toString() {
    return 'PairingCommandDto.persistRing(ringId: $ringId)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_PersistRingImpl &&
            const DeepCollectionEquality().equals(other.ringId, ringId));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(ringId));

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_PersistRingImplCopyWith<
          _$PairingCommandDto_PersistRingImpl>
      get copyWith => __$$PairingCommandDto_PersistRingImplCopyWithImpl<
          _$PairingCommandDto_PersistRingImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return persistRing(ringId);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return persistRing?.call(ringId);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (persistRing != null) {
      return persistRing(ringId);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return persistRing(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return persistRing?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (persistRing != null) {
      return persistRing(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_PersistRing extends PairingCommandDto {
  const factory PairingCommandDto_PersistRing(
      {required final Uint8List ringId}) = _$PairingCommandDto_PersistRingImpl;
  const PairingCommandDto_PersistRing._() : super._();

  Uint8List get ringId;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_PersistRingImplCopyWith<
          _$PairingCommandDto_PersistRingImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_RosterReceivedImplCopyWith<$Res> {
  factory _$$PairingCommandDto_RosterReceivedImplCopyWith(
          _$PairingCommandDto_RosterReceivedImpl value,
          $Res Function(_$PairingCommandDto_RosterReceivedImpl) then) =
      __$$PairingCommandDto_RosterReceivedImplCopyWithImpl<$Res>;
  @useResult
  $Res call({List<SiblingInfoDto> roster});
}

/// @nodoc
class __$$PairingCommandDto_RosterReceivedImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_RosterReceivedImpl>
    implements _$$PairingCommandDto_RosterReceivedImplCopyWith<$Res> {
  __$$PairingCommandDto_RosterReceivedImplCopyWithImpl(
      _$PairingCommandDto_RosterReceivedImpl _value,
      $Res Function(_$PairingCommandDto_RosterReceivedImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? roster = null,
  }) {
    return _then(_$PairingCommandDto_RosterReceivedImpl(
      roster: null == roster
          ? _value._roster
          : roster // ignore: cast_nullable_to_non_nullable
              as List<SiblingInfoDto>,
    ));
  }
}

/// @nodoc

class _$PairingCommandDto_RosterReceivedImpl
    extends PairingCommandDto_RosterReceived {
  const _$PairingCommandDto_RosterReceivedImpl(
      {required final List<SiblingInfoDto> roster})
      : _roster = roster,
        super._();

  final List<SiblingInfoDto> _roster;
  @override
  List<SiblingInfoDto> get roster {
    if (_roster is EqualUnmodifiableListView) return _roster;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_roster);
  }

  @override
  String toString() {
    return 'PairingCommandDto.rosterReceived(roster: $roster)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_RosterReceivedImpl &&
            const DeepCollectionEquality().equals(other._roster, _roster));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(_roster));

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_RosterReceivedImplCopyWith<
          _$PairingCommandDto_RosterReceivedImpl>
      get copyWith => __$$PairingCommandDto_RosterReceivedImplCopyWithImpl<
          _$PairingCommandDto_RosterReceivedImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return rosterReceived(roster);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return rosterReceived?.call(roster);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (rosterReceived != null) {
      return rosterReceived(roster);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return rosterReceived(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return rosterReceived?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (rosterReceived != null) {
      return rosterReceived(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_RosterReceived extends PairingCommandDto {
  const factory PairingCommandDto_RosterReceived(
          {required final List<SiblingInfoDto> roster}) =
      _$PairingCommandDto_RosterReceivedImpl;
  const PairingCommandDto_RosterReceived._() : super._();

  List<SiblingInfoDto> get roster;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_RosterReceivedImplCopyWith<
          _$PairingCommandDto_RosterReceivedImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_StartSyncImplCopyWith<$Res> {
  factory _$$PairingCommandDto_StartSyncImplCopyWith(
          _$PairingCommandDto_StartSyncImpl value,
          $Res Function(_$PairingCommandDto_StartSyncImpl) then) =
      __$$PairingCommandDto_StartSyncImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$PairingCommandDto_StartSyncImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_StartSyncImpl>
    implements _$$PairingCommandDto_StartSyncImplCopyWith<$Res> {
  __$$PairingCommandDto_StartSyncImplCopyWithImpl(
      _$PairingCommandDto_StartSyncImpl _value,
      $Res Function(_$PairingCommandDto_StartSyncImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$PairingCommandDto_StartSyncImpl extends PairingCommandDto_StartSync {
  const _$PairingCommandDto_StartSyncImpl() : super._();

  @override
  String toString() {
    return 'PairingCommandDto.startSync()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_StartSyncImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return startSync();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return startSync?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (startSync != null) {
      return startSync();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return startSync(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return startSync?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (startSync != null) {
      return startSync(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_StartSync extends PairingCommandDto {
  const factory PairingCommandDto_StartSync() =
      _$PairingCommandDto_StartSyncImpl;
  const PairingCommandDto_StartSync._() : super._();
}

/// @nodoc
mixin _$RingCommandDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishStealthEvent,
    required TResult Function() replenishKeyPackage,
    required TResult Function(Uint8List groupId, GroupKindDto kind)
        registerGroup,
    required TResult Function() pollForNewDevices,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult? Function()? replenishKeyPackage,
    TResult? Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult? Function()? pollForNewDevices,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult Function()? replenishKeyPackage,
    TResult Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult Function()? pollForNewDevices,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingCommandDto_PublishStealthEvent value)
        publishStealthEvent,
    required TResult Function(RingCommandDto_ReplenishKeyPackage value)
        replenishKeyPackage,
    required TResult Function(RingCommandDto_RegisterGroup value) registerGroup,
    required TResult Function(RingCommandDto_PollForNewDevices value)
        pollForNewDevices,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult? Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult? Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult? Function(RingCommandDto_PollForNewDevices value)?
        pollForNewDevices,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult Function(RingCommandDto_PollForNewDevices value)? pollForNewDevices,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $RingCommandDtoCopyWith<$Res> {
  factory $RingCommandDtoCopyWith(
          RingCommandDto value, $Res Function(RingCommandDto) then) =
      _$RingCommandDtoCopyWithImpl<$Res, RingCommandDto>;
}

/// @nodoc
class _$RingCommandDtoCopyWithImpl<$Res, $Val extends RingCommandDto>
    implements $RingCommandDtoCopyWith<$Res> {
  _$RingCommandDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$RingCommandDto_PublishStealthEventImplCopyWith<$Res> {
  factory _$$RingCommandDto_PublishStealthEventImplCopyWith(
          _$RingCommandDto_PublishStealthEventImpl value,
          $Res Function(_$RingCommandDto_PublishStealthEventImpl) then) =
      __$$RingCommandDto_PublishStealthEventImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List tag, Uint8List ciphertext});
}

/// @nodoc
class __$$RingCommandDto_PublishStealthEventImplCopyWithImpl<$Res>
    extends _$RingCommandDtoCopyWithImpl<$Res,
        _$RingCommandDto_PublishStealthEventImpl>
    implements _$$RingCommandDto_PublishStealthEventImplCopyWith<$Res> {
  __$$RingCommandDto_PublishStealthEventImplCopyWithImpl(
      _$RingCommandDto_PublishStealthEventImpl _value,
      $Res Function(_$RingCommandDto_PublishStealthEventImpl) _then)
      : super(_value, _then);

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? tag = null,
    Object? ciphertext = null,
  }) {
    return _then(_$RingCommandDto_PublishStealthEventImpl(
      tag: null == tag
          ? _value.tag
          : tag // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      ciphertext: null == ciphertext
          ? _value.ciphertext
          : ciphertext // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$RingCommandDto_PublishStealthEventImpl
    extends RingCommandDto_PublishStealthEvent {
  const _$RingCommandDto_PublishStealthEventImpl(
      {required this.tag, required this.ciphertext})
      : super._();

  @override
  final Uint8List tag;
  @override
  final Uint8List ciphertext;

  @override
  String toString() {
    return 'RingCommandDto.publishStealthEvent(tag: $tag, ciphertext: $ciphertext)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$RingCommandDto_PublishStealthEventImpl &&
            const DeepCollectionEquality().equals(other.tag, tag) &&
            const DeepCollectionEquality()
                .equals(other.ciphertext, ciphertext));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType,
      const DeepCollectionEquality().hash(tag),
      const DeepCollectionEquality().hash(ciphertext));

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$RingCommandDto_PublishStealthEventImplCopyWith<
          _$RingCommandDto_PublishStealthEventImpl>
      get copyWith => __$$RingCommandDto_PublishStealthEventImplCopyWithImpl<
          _$RingCommandDto_PublishStealthEventImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishStealthEvent,
    required TResult Function() replenishKeyPackage,
    required TResult Function(Uint8List groupId, GroupKindDto kind)
        registerGroup,
    required TResult Function() pollForNewDevices,
  }) {
    return publishStealthEvent(tag, ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult? Function()? replenishKeyPackage,
    TResult? Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult? Function()? pollForNewDevices,
  }) {
    return publishStealthEvent?.call(tag, ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult Function()? replenishKeyPackage,
    TResult Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult Function()? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (publishStealthEvent != null) {
      return publishStealthEvent(tag, ciphertext);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingCommandDto_PublishStealthEvent value)
        publishStealthEvent,
    required TResult Function(RingCommandDto_ReplenishKeyPackage value)
        replenishKeyPackage,
    required TResult Function(RingCommandDto_RegisterGroup value) registerGroup,
    required TResult Function(RingCommandDto_PollForNewDevices value)
        pollForNewDevices,
  }) {
    return publishStealthEvent(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult? Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult? Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult? Function(RingCommandDto_PollForNewDevices value)?
        pollForNewDevices,
  }) {
    return publishStealthEvent?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult Function(RingCommandDto_PollForNewDevices value)? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (publishStealthEvent != null) {
      return publishStealthEvent(this);
    }
    return orElse();
  }
}

abstract class RingCommandDto_PublishStealthEvent extends RingCommandDto {
  const factory RingCommandDto_PublishStealthEvent(
          {required final Uint8List tag, required final Uint8List ciphertext}) =
      _$RingCommandDto_PublishStealthEventImpl;
  const RingCommandDto_PublishStealthEvent._() : super._();

  Uint8List get tag;
  Uint8List get ciphertext;

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$RingCommandDto_PublishStealthEventImplCopyWith<
          _$RingCommandDto_PublishStealthEventImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$RingCommandDto_ReplenishKeyPackageImplCopyWith<$Res> {
  factory _$$RingCommandDto_ReplenishKeyPackageImplCopyWith(
          _$RingCommandDto_ReplenishKeyPackageImpl value,
          $Res Function(_$RingCommandDto_ReplenishKeyPackageImpl) then) =
      __$$RingCommandDto_ReplenishKeyPackageImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$RingCommandDto_ReplenishKeyPackageImplCopyWithImpl<$Res>
    extends _$RingCommandDtoCopyWithImpl<$Res,
        _$RingCommandDto_ReplenishKeyPackageImpl>
    implements _$$RingCommandDto_ReplenishKeyPackageImplCopyWith<$Res> {
  __$$RingCommandDto_ReplenishKeyPackageImplCopyWithImpl(
      _$RingCommandDto_ReplenishKeyPackageImpl _value,
      $Res Function(_$RingCommandDto_ReplenishKeyPackageImpl) _then)
      : super(_value, _then);

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$RingCommandDto_ReplenishKeyPackageImpl
    extends RingCommandDto_ReplenishKeyPackage {
  const _$RingCommandDto_ReplenishKeyPackageImpl() : super._();

  @override
  String toString() {
    return 'RingCommandDto.replenishKeyPackage()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$RingCommandDto_ReplenishKeyPackageImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishStealthEvent,
    required TResult Function() replenishKeyPackage,
    required TResult Function(Uint8List groupId, GroupKindDto kind)
        registerGroup,
    required TResult Function() pollForNewDevices,
  }) {
    return replenishKeyPackage();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult? Function()? replenishKeyPackage,
    TResult? Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult? Function()? pollForNewDevices,
  }) {
    return replenishKeyPackage?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult Function()? replenishKeyPackage,
    TResult Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult Function()? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (replenishKeyPackage != null) {
      return replenishKeyPackage();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingCommandDto_PublishStealthEvent value)
        publishStealthEvent,
    required TResult Function(RingCommandDto_ReplenishKeyPackage value)
        replenishKeyPackage,
    required TResult Function(RingCommandDto_RegisterGroup value) registerGroup,
    required TResult Function(RingCommandDto_PollForNewDevices value)
        pollForNewDevices,
  }) {
    return replenishKeyPackage(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult? Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult? Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult? Function(RingCommandDto_PollForNewDevices value)?
        pollForNewDevices,
  }) {
    return replenishKeyPackage?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult Function(RingCommandDto_PollForNewDevices value)? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (replenishKeyPackage != null) {
      return replenishKeyPackage(this);
    }
    return orElse();
  }
}

abstract class RingCommandDto_ReplenishKeyPackage extends RingCommandDto {
  const factory RingCommandDto_ReplenishKeyPackage() =
      _$RingCommandDto_ReplenishKeyPackageImpl;
  const RingCommandDto_ReplenishKeyPackage._() : super._();
}

/// @nodoc
abstract class _$$RingCommandDto_RegisterGroupImplCopyWith<$Res> {
  factory _$$RingCommandDto_RegisterGroupImplCopyWith(
          _$RingCommandDto_RegisterGroupImpl value,
          $Res Function(_$RingCommandDto_RegisterGroupImpl) then) =
      __$$RingCommandDto_RegisterGroupImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List groupId, GroupKindDto kind});
}

/// @nodoc
class __$$RingCommandDto_RegisterGroupImplCopyWithImpl<$Res>
    extends _$RingCommandDtoCopyWithImpl<$Res,
        _$RingCommandDto_RegisterGroupImpl>
    implements _$$RingCommandDto_RegisterGroupImplCopyWith<$Res> {
  __$$RingCommandDto_RegisterGroupImplCopyWithImpl(
      _$RingCommandDto_RegisterGroupImpl _value,
      $Res Function(_$RingCommandDto_RegisterGroupImpl) _then)
      : super(_value, _then);

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? groupId = null,
    Object? kind = null,
  }) {
    return _then(_$RingCommandDto_RegisterGroupImpl(
      groupId: null == groupId
          ? _value.groupId
          : groupId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      kind: null == kind
          ? _value.kind
          : kind // ignore: cast_nullable_to_non_nullable
              as GroupKindDto,
    ));
  }
}

/// @nodoc

class _$RingCommandDto_RegisterGroupImpl extends RingCommandDto_RegisterGroup {
  const _$RingCommandDto_RegisterGroupImpl(
      {required this.groupId, required this.kind})
      : super._();

  @override
  final Uint8List groupId;
  @override
  final GroupKindDto kind;

  @override
  String toString() {
    return 'RingCommandDto.registerGroup(groupId: $groupId, kind: $kind)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$RingCommandDto_RegisterGroupImpl &&
            const DeepCollectionEquality().equals(other.groupId, groupId) &&
            (identical(other.kind, kind) || other.kind == kind));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType, const DeepCollectionEquality().hash(groupId), kind);

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$RingCommandDto_RegisterGroupImplCopyWith<
          _$RingCommandDto_RegisterGroupImpl>
      get copyWith => __$$RingCommandDto_RegisterGroupImplCopyWithImpl<
          _$RingCommandDto_RegisterGroupImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishStealthEvent,
    required TResult Function() replenishKeyPackage,
    required TResult Function(Uint8List groupId, GroupKindDto kind)
        registerGroup,
    required TResult Function() pollForNewDevices,
  }) {
    return registerGroup(groupId, kind);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult? Function()? replenishKeyPackage,
    TResult? Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult? Function()? pollForNewDevices,
  }) {
    return registerGroup?.call(groupId, kind);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult Function()? replenishKeyPackage,
    TResult Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult Function()? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (registerGroup != null) {
      return registerGroup(groupId, kind);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingCommandDto_PublishStealthEvent value)
        publishStealthEvent,
    required TResult Function(RingCommandDto_ReplenishKeyPackage value)
        replenishKeyPackage,
    required TResult Function(RingCommandDto_RegisterGroup value) registerGroup,
    required TResult Function(RingCommandDto_PollForNewDevices value)
        pollForNewDevices,
  }) {
    return registerGroup(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult? Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult? Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult? Function(RingCommandDto_PollForNewDevices value)?
        pollForNewDevices,
  }) {
    return registerGroup?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult Function(RingCommandDto_PollForNewDevices value)? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (registerGroup != null) {
      return registerGroup(this);
    }
    return orElse();
  }
}

abstract class RingCommandDto_RegisterGroup extends RingCommandDto {
  const factory RingCommandDto_RegisterGroup(
      {required final Uint8List groupId,
      required final GroupKindDto kind}) = _$RingCommandDto_RegisterGroupImpl;
  const RingCommandDto_RegisterGroup._() : super._();

  Uint8List get groupId;
  GroupKindDto get kind;

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$RingCommandDto_RegisterGroupImplCopyWith<
          _$RingCommandDto_RegisterGroupImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$RingCommandDto_PollForNewDevicesImplCopyWith<$Res> {
  factory _$$RingCommandDto_PollForNewDevicesImplCopyWith(
          _$RingCommandDto_PollForNewDevicesImpl value,
          $Res Function(_$RingCommandDto_PollForNewDevicesImpl) then) =
      __$$RingCommandDto_PollForNewDevicesImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$RingCommandDto_PollForNewDevicesImplCopyWithImpl<$Res>
    extends _$RingCommandDtoCopyWithImpl<$Res,
        _$RingCommandDto_PollForNewDevicesImpl>
    implements _$$RingCommandDto_PollForNewDevicesImplCopyWith<$Res> {
  __$$RingCommandDto_PollForNewDevicesImplCopyWithImpl(
      _$RingCommandDto_PollForNewDevicesImpl _value,
      $Res Function(_$RingCommandDto_PollForNewDevicesImpl) _then)
      : super(_value, _then);

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$RingCommandDto_PollForNewDevicesImpl
    extends RingCommandDto_PollForNewDevices {
  const _$RingCommandDto_PollForNewDevicesImpl() : super._();

  @override
  String toString() {
    return 'RingCommandDto.pollForNewDevices()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$RingCommandDto_PollForNewDevicesImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishStealthEvent,
    required TResult Function() replenishKeyPackage,
    required TResult Function(Uint8List groupId, GroupKindDto kind)
        registerGroup,
    required TResult Function() pollForNewDevices,
  }) {
    return pollForNewDevices();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult? Function()? replenishKeyPackage,
    TResult? Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult? Function()? pollForNewDevices,
  }) {
    return pollForNewDevices?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult Function()? replenishKeyPackage,
    TResult Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult Function()? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (pollForNewDevices != null) {
      return pollForNewDevices();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingCommandDto_PublishStealthEvent value)
        publishStealthEvent,
    required TResult Function(RingCommandDto_ReplenishKeyPackage value)
        replenishKeyPackage,
    required TResult Function(RingCommandDto_RegisterGroup value) registerGroup,
    required TResult Function(RingCommandDto_PollForNewDevices value)
        pollForNewDevices,
  }) {
    return pollForNewDevices(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult? Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult? Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult? Function(RingCommandDto_PollForNewDevices value)?
        pollForNewDevices,
  }) {
    return pollForNewDevices?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult Function(RingCommandDto_PollForNewDevices value)? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (pollForNewDevices != null) {
      return pollForNewDevices(this);
    }
    return orElse();
  }
}

abstract class RingCommandDto_PollForNewDevices extends RingCommandDto {
  const factory RingCommandDto_PollForNewDevices() =
      _$RingCommandDto_PollForNewDevicesImpl;
  const RingCommandDto_PollForNewDevices._() : super._();
}

/// @nodoc
mixin _$SyncOutputDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List bytes) send,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        store,
    required TResult Function() complete,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List bytes)? send,
    TResult? Function(String convId, List<SyncMessageDto> messages)? store,
    TResult? Function()? complete,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List bytes)? send,
    TResult Function(String convId, List<SyncMessageDto> messages)? store,
    TResult Function()? complete,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncOutputDto_Send value) send,
    required TResult Function(SyncOutputDto_Store value) store,
    required TResult Function(SyncOutputDto_Complete value) complete,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncOutputDto_Send value)? send,
    TResult? Function(SyncOutputDto_Store value)? store,
    TResult? Function(SyncOutputDto_Complete value)? complete,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncOutputDto_Send value)? send,
    TResult Function(SyncOutputDto_Store value)? store,
    TResult Function(SyncOutputDto_Complete value)? complete,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SyncOutputDtoCopyWith<$Res> {
  factory $SyncOutputDtoCopyWith(
          SyncOutputDto value, $Res Function(SyncOutputDto) then) =
      _$SyncOutputDtoCopyWithImpl<$Res, SyncOutputDto>;
}

/// @nodoc
class _$SyncOutputDtoCopyWithImpl<$Res, $Val extends SyncOutputDto>
    implements $SyncOutputDtoCopyWith<$Res> {
  _$SyncOutputDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$SyncOutputDto_SendImplCopyWith<$Res> {
  factory _$$SyncOutputDto_SendImplCopyWith(_$SyncOutputDto_SendImpl value,
          $Res Function(_$SyncOutputDto_SendImpl) then) =
      __$$SyncOutputDto_SendImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List bytes});
}

/// @nodoc
class __$$SyncOutputDto_SendImplCopyWithImpl<$Res>
    extends _$SyncOutputDtoCopyWithImpl<$Res, _$SyncOutputDto_SendImpl>
    implements _$$SyncOutputDto_SendImplCopyWith<$Res> {
  __$$SyncOutputDto_SendImplCopyWithImpl(_$SyncOutputDto_SendImpl _value,
      $Res Function(_$SyncOutputDto_SendImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? bytes = null,
  }) {
    return _then(_$SyncOutputDto_SendImpl(
      bytes: null == bytes
          ? _value.bytes
          : bytes // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$SyncOutputDto_SendImpl extends SyncOutputDto_Send {
  const _$SyncOutputDto_SendImpl({required this.bytes}) : super._();

  @override
  final Uint8List bytes;

  @override
  String toString() {
    return 'SyncOutputDto.send(bytes: $bytes)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncOutputDto_SendImpl &&
            const DeepCollectionEquality().equals(other.bytes, bytes));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(bytes));

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SyncOutputDto_SendImplCopyWith<_$SyncOutputDto_SendImpl> get copyWith =>
      __$$SyncOutputDto_SendImplCopyWithImpl<_$SyncOutputDto_SendImpl>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List bytes) send,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        store,
    required TResult Function() complete,
  }) {
    return send(bytes);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List bytes)? send,
    TResult? Function(String convId, List<SyncMessageDto> messages)? store,
    TResult? Function()? complete,
  }) {
    return send?.call(bytes);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List bytes)? send,
    TResult Function(String convId, List<SyncMessageDto> messages)? store,
    TResult Function()? complete,
    required TResult orElse(),
  }) {
    if (send != null) {
      return send(bytes);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncOutputDto_Send value) send,
    required TResult Function(SyncOutputDto_Store value) store,
    required TResult Function(SyncOutputDto_Complete value) complete,
  }) {
    return send(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncOutputDto_Send value)? send,
    TResult? Function(SyncOutputDto_Store value)? store,
    TResult? Function(SyncOutputDto_Complete value)? complete,
  }) {
    return send?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncOutputDto_Send value)? send,
    TResult Function(SyncOutputDto_Store value)? store,
    TResult Function(SyncOutputDto_Complete value)? complete,
    required TResult orElse(),
  }) {
    if (send != null) {
      return send(this);
    }
    return orElse();
  }
}

abstract class SyncOutputDto_Send extends SyncOutputDto {
  const factory SyncOutputDto_Send({required final Uint8List bytes}) =
      _$SyncOutputDto_SendImpl;
  const SyncOutputDto_Send._() : super._();

  Uint8List get bytes;

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SyncOutputDto_SendImplCopyWith<_$SyncOutputDto_SendImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$SyncOutputDto_StoreImplCopyWith<$Res> {
  factory _$$SyncOutputDto_StoreImplCopyWith(_$SyncOutputDto_StoreImpl value,
          $Res Function(_$SyncOutputDto_StoreImpl) then) =
      __$$SyncOutputDto_StoreImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String convId, List<SyncMessageDto> messages});
}

/// @nodoc
class __$$SyncOutputDto_StoreImplCopyWithImpl<$Res>
    extends _$SyncOutputDtoCopyWithImpl<$Res, _$SyncOutputDto_StoreImpl>
    implements _$$SyncOutputDto_StoreImplCopyWith<$Res> {
  __$$SyncOutputDto_StoreImplCopyWithImpl(_$SyncOutputDto_StoreImpl _value,
      $Res Function(_$SyncOutputDto_StoreImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? convId = null,
    Object? messages = null,
  }) {
    return _then(_$SyncOutputDto_StoreImpl(
      convId: null == convId
          ? _value.convId
          : convId // ignore: cast_nullable_to_non_nullable
              as String,
      messages: null == messages
          ? _value._messages
          : messages // ignore: cast_nullable_to_non_nullable
              as List<SyncMessageDto>,
    ));
  }
}

/// @nodoc

class _$SyncOutputDto_StoreImpl extends SyncOutputDto_Store {
  const _$SyncOutputDto_StoreImpl(
      {required this.convId, required final List<SyncMessageDto> messages})
      : _messages = messages,
        super._();

  @override
  final String convId;
  final List<SyncMessageDto> _messages;
  @override
  List<SyncMessageDto> get messages {
    if (_messages is EqualUnmodifiableListView) return _messages;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_messages);
  }

  @override
  String toString() {
    return 'SyncOutputDto.store(convId: $convId, messages: $messages)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncOutputDto_StoreImpl &&
            (identical(other.convId, convId) || other.convId == convId) &&
            const DeepCollectionEquality().equals(other._messages, _messages));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType, convId, const DeepCollectionEquality().hash(_messages));

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SyncOutputDto_StoreImplCopyWith<_$SyncOutputDto_StoreImpl> get copyWith =>
      __$$SyncOutputDto_StoreImplCopyWithImpl<_$SyncOutputDto_StoreImpl>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List bytes) send,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        store,
    required TResult Function() complete,
  }) {
    return store(convId, messages);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List bytes)? send,
    TResult? Function(String convId, List<SyncMessageDto> messages)? store,
    TResult? Function()? complete,
  }) {
    return store?.call(convId, messages);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List bytes)? send,
    TResult Function(String convId, List<SyncMessageDto> messages)? store,
    TResult Function()? complete,
    required TResult orElse(),
  }) {
    if (store != null) {
      return store(convId, messages);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncOutputDto_Send value) send,
    required TResult Function(SyncOutputDto_Store value) store,
    required TResult Function(SyncOutputDto_Complete value) complete,
  }) {
    return store(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncOutputDto_Send value)? send,
    TResult? Function(SyncOutputDto_Store value)? store,
    TResult? Function(SyncOutputDto_Complete value)? complete,
  }) {
    return store?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncOutputDto_Send value)? send,
    TResult Function(SyncOutputDto_Store value)? store,
    TResult Function(SyncOutputDto_Complete value)? complete,
    required TResult orElse(),
  }) {
    if (store != null) {
      return store(this);
    }
    return orElse();
  }
}

abstract class SyncOutputDto_Store extends SyncOutputDto {
  const factory SyncOutputDto_Store(
          {required final String convId,
          required final List<SyncMessageDto> messages}) =
      _$SyncOutputDto_StoreImpl;
  const SyncOutputDto_Store._() : super._();

  String get convId;
  List<SyncMessageDto> get messages;

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SyncOutputDto_StoreImplCopyWith<_$SyncOutputDto_StoreImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$SyncOutputDto_CompleteImplCopyWith<$Res> {
  factory _$$SyncOutputDto_CompleteImplCopyWith(
          _$SyncOutputDto_CompleteImpl value,
          $Res Function(_$SyncOutputDto_CompleteImpl) then) =
      __$$SyncOutputDto_CompleteImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SyncOutputDto_CompleteImplCopyWithImpl<$Res>
    extends _$SyncOutputDtoCopyWithImpl<$Res, _$SyncOutputDto_CompleteImpl>
    implements _$$SyncOutputDto_CompleteImplCopyWith<$Res> {
  __$$SyncOutputDto_CompleteImplCopyWithImpl(
      _$SyncOutputDto_CompleteImpl _value,
      $Res Function(_$SyncOutputDto_CompleteImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SyncOutputDto_CompleteImpl extends SyncOutputDto_Complete {
  const _$SyncOutputDto_CompleteImpl() : super._();

  @override
  String toString() {
    return 'SyncOutputDto.complete()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncOutputDto_CompleteImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List bytes) send,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        store,
    required TResult Function() complete,
  }) {
    return complete();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List bytes)? send,
    TResult? Function(String convId, List<SyncMessageDto> messages)? store,
    TResult? Function()? complete,
  }) {
    return complete?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List bytes)? send,
    TResult Function(String convId, List<SyncMessageDto> messages)? store,
    TResult Function()? complete,
    required TResult orElse(),
  }) {
    if (complete != null) {
      return complete();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncOutputDto_Send value) send,
    required TResult Function(SyncOutputDto_Store value) store,
    required TResult Function(SyncOutputDto_Complete value) complete,
  }) {
    return complete(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncOutputDto_Send value)? send,
    TResult? Function(SyncOutputDto_Store value)? store,
    TResult? Function(SyncOutputDto_Complete value)? complete,
  }) {
    return complete?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncOutputDto_Send value)? send,
    TResult Function(SyncOutputDto_Store value)? store,
    TResult Function(SyncOutputDto_Complete value)? complete,
    required TResult orElse(),
  }) {
    if (complete != null) {
      return complete(this);
    }
    return orElse();
  }
}

abstract class SyncOutputDto_Complete extends SyncOutputDto {
  const factory SyncOutputDto_Complete() = _$SyncOutputDto_CompleteImpl;
  const SyncOutputDto_Complete._() : super._();
}
