import { IsEmail, IsOptional, IsString, Length, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(12)
  password: string;

  @IsString()
  @Length(1, 100)
  first_name: string;

  @IsString()
  @Length(1, 100)
  last_name: string;
}

export class LoginDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;

  @IsOptional()
  @IsString()
  @Length(0, 512)
  device_fingerprint?: string;
}

export class MfaVerifyDto {
  @IsString()
  @Length(6, 6)
  code: string;
}
