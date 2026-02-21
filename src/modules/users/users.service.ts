import {
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    @InjectRepository(User)
    private usersRepo: Repository<User>,
  ) {}

  async findAll(): Promise<User[]> {
    try {
      const users = await this.usersRepo.find({
        order: {
          id: 'ASC',
        },
      });
      return users;
    } catch (error) {
      this.logger.error('Failed to fetch users', String(error));
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  async findOne(id: number): Promise<User> {
    try {
      const user = await this.usersRepo.findOneBy({ id });
      if (!user) {
        throw new NotFoundException('User not found');
      }
      return user;
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(`Failed to fetch user with id ${id}`, String(error));
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  async update(id: number, updateUserDto: UpdateUserDto): Promise<User> {
    try {
      const user = await this.usersRepo.findOneBy({ id });
      if (!user) {
        throw new NotFoundException('User not found');
      }
      return this.usersRepo.save({ ...user, ...updateUserDto });
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(`Failed to update user with id ${id}`, String(error));
      throw new InternalServerErrorException('Something went wrong');
    }
  }
}
